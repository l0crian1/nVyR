import asyncio
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import time
import pytest

from nvyr.cli import CLI, TreeSuggestion
from nvyr.errors import RouterError
from nvyr.protocol import Client, MAX_FRAME, VERSION, encode, receive


def test_anchored_prompt_prediction_tab_help_rpc_and_persistence(daemon, monkeypatch):
    from prompt_toolkit.document import Document
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    async def scenario():
        client = Client(daemon)
        cli = CLI(client, emit=lambda _: None)
        displayed = []
        monkeypatch.setattr('nvyr.cli.print_formatted_text', displayed.append)
        prefix = 'set firewall ipv4 forward filter rule 10 action accept pro'

        async def until(condition):
            deadline = time.monotonic() + 3

            while not condition():
                assert time.monotonic() < deadline

                await asyncio.sleep(.025)

        try:
            cli.submit('configure')
            suggestion = TreeSuggestion(cli).get_suggestion(None, Document(prefix, len(prefix)))

            assert suggestion.text == 'tocol'

            with create_pipe_input() as pipe:
                prompt = cli.make_prompts(input=pipe, output=DummyOutput())['configuration']
                pending = asyncio.create_task(prompt.prompt_async('router# '))
                pipe.send_text('\x1b[200~' + prefix + '\x1b[201~\t')
                await until(lambda: prompt.default_buffer.text.endswith('protocol '))
                pipe.send_text('tcp ?')
                await until(lambda: bool(displayed))

                assert 'destination-port' in displayed[-1] and '<Enter>' in displayed[-1]

                pipe.send_text('destination-p\t')
                # Port and port-group share this prefix; Tab cannot select one yet.
                await until(lambda: prompt.default_buffer.text.endswith('destination-port'))
                pipe.send_text(' ')
                await until(lambda: prompt.default_buffer.text.endswith('destination-port '))
                pipe.send_text('22\r')
                command = await asyncio.wait_for(pending, 3)
                cli.submit(command)

            expected = client.request('execute', text='show candidate-configuration | commands')['text']

            assert len(expected.splitlines()) == 3

            with pytest.raises(RouterError, match='Invalid value'):
                client.request('execute', text='set firewall ipv4 forward filter rule 10 action drop protocol invalid')

            assert client.request('execute', text='show candidate-configuration | commands')['text'] == expected

            cli.submit('commit\nsave\nexit')
        finally:
            client.close()

        client = Client(daemon)

        try:
            running = json.loads(client.request('execute', text='show running-configuration')['text'])

            assert running['firewall']['ipv4']['forward']['filter']['rule']['10'] == {
                'action': 'accept', 'protocol': ['tcp'], 'destination-port': ['22']}
        finally:
            client.close()

    asyncio.run(scenario())


def test_invalid_tag_prompt_suggestion_tab_and_help(daemon, monkeypatch):
    from prompt_toolkit.document import Document
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    async def scenario():
        client = Client(daemon)
        cli = CLI(client, emit=lambda _: None)
        displayed = []
        monkeypatch.setattr('nvyr.cli.print_formatted_text', displayed.append)

        async def until(condition):
            deadline = time.monotonic() + 3

            while not condition():
                assert time.monotonic() < deadline

                await asyncio.sleep(.025)

        try:
            cli.submit('configure')
            prefix = 'set interfaces dummy dm0 des'

            assert TreeSuggestion(cli).get_suggestion(None, Document(prefix, len(prefix))).text == 'cription'

            with create_pipe_input() as pipe:
                prompt = cli.make_prompts(input=pipe, output=DummyOutput())['configuration']
                pending = asyncio.create_task(prompt.prompt_async('router# '))
                pipe.send_text('\x1b[200~set interfaces dummy \x1b[201~?')
                await until(lambda: bool(displayed))

                assert 'dumN' in displayed[-1] and 'Dummy interface name' in displayed[-1]

                pipe.send_text('dm0 ?')
                await until(lambda: len(displayed) >= 2)

                assert 'address' in displayed[-1] and 'mtu' in displayed[-1]

                pipe.send_text('des\t')
                await until(lambda: prompt.default_buffer.text.endswith('description '))
                pipe.send_text('"Invalid interface"\r')
                command = await asyncio.wait_for(pending, 3)

            with pytest.raises(RouterError, match='regular expression'):
                client.request('execute', text=command)

            assert client.request('execute', text='show candidate-configuration | commands').get('text', '') == ''
        finally:
            client.close()

    asyncio.run(scenario())


@pytest.fixture
def daemon(tmp_path, request):
    from build_tools.op_scripts import install_scripts

    # Mirror deployment: operational programs are executable PATH symlinks.
    scripts = tmp_path / 'op_scripts'
    shutil.copytree(Path(__file__).resolve().parents[1] / 'src/nvyr/op_scripts', scripts)
    install_scripts(scripts, tmp_path / 'bin')
    environment = dict(os.environ, PATH=str(tmp_path / 'bin') + os.pathsep + os.environ['PATH'])
    path = tmp_path / "configd.sock"
    log = open(tmp_path / "daemon.log", "w+")
    schema_setup = ''

    if hasattr(request, 'param'):
        schema_setup = ('from nvyr.schema import Schema; _bundled = Schema.bundled; '
                        'Schema.bundled = classmethod(lambda cls, name="configuration", **kw: '
                        f'cls({request.param!r}, **kw) if name == "operational" else _bundled(name, **kw)); ')

    # These transport/CLI tests use a trusted test identity, independent of the
    # Linux account running pytest. Role and real peer-credential checks have
    # their own fixtures; this does not elevate the daemon process.
    startup = ('from functools import partial; '
               'import nvyr.daemon as daemon; '
               'daemon.Server = partial(daemon.Server, identity=lambda writer: ("root", "test-client")); '
               'from nvyr.helpers import interfaces; '
               'from nvyr.helpers import accounts; accounts.initialize = lambda *args: None; '
               'accounts.manager.apply = lambda *args, **kwargs: None; '
               'interfaces.manager.validate = lambda *args, **kwargs: None; '
               'interfaces.manager.request = lambda *args, **kwargs: {}; '
               'from nvyr.helpers import nftables; nftables.manager.apply = lambda *args, **kwargs: None; '
               'nftables.manager.named_chains = lambda: []; '
               'nftables.manager.flowtables = lambda: []; '
               'nftables.manager.maps = lambda: []; '
               'nftables.manager.match_groups = lambda: []; '
               'nftables.manager.singleton_groups = lambda: []; '
               'nftables.manager.icmp_groups = lambda: []; '
               'nftables.manager.rule_limits = lambda: []; '
               'nftables.manager.named_state = lambda: []; '
               'nftables.manager.table_exists = lambda name: False; '
               # Match the in-process fixture: transport tests must not apply
               # firewall kernel defaults to the machine running the tests.
               'from contextlib import nullcontext; '
               'from nvyr.helpers import kernel_settings; '
               'kernel_settings.manager.transaction = lambda *a, **k: nullcontext(); '
               'from nvyr.helpers import ssh; ssh.manager.apply = lambda *args, **kwargs: None; '
               'from nvyr.helpers import ntp; ntp.manager.apply = lambda *args, **kwargs: None; '
               'from nvyr.helpers import kea; kea.manager.apply = lambda *args, **kwargs: None; '
               'from nvyr.config_scripts import container; container.generate = lambda *args, **kwargs: None; container.worker.run_apply = lambda *args, **kwargs: None; '
               'interfaces.manager.replace = lambda *args, **kwargs: None; '
               'from nvyr.helpers import frr_reload; frr_reload.manager.apply = lambda *a, **k: None; '
               'from nvyr.helpers import logging_runtime; '
               'import logging; logging_runtime.configure_python = lambda name: logging.basicConfig(level=logging.INFO); '
               'logging_runtime.install = lambda *a, **k: None; '
               'logging_runtime.prepare_groups = lambda *a, **k: None; '
               'logging_runtime.cleanup = lambda *a, **k: None; '
               'from nvyr.helpers import system; system.apply_hostname = lambda *args, **kwargs: None; '
               'daemon.main()')
    process = subprocess.Popen([sys.executable, "-c", schema_setup + startup, "--state", str(tmp_path / "state"), "--socket", str(path)], stdout=log, stderr=log, env=environment)
    deadline = time.monotonic() + 10

    try:
        while not path.exists():
            if process.poll() is not None or time.monotonic() > deadline:
                log.seek(0)
                pytest.fail(log.read() or "Daemon failed to start")

            time.sleep(.02)

        yield path
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        log.close()


def test_operational_scripts_dispatch_through_configd(daemon):
    client = Client(daemon)

    try:
        assert '127.0.0.1/8' in client.request('execute', text='show interfaces')['text']
        assert '127.0.0.1/8' in client.request('execute', text='show interfaces lo')['text']
        assert 'ethernet' in dict(client.request('complete', text='show interfaces ', explicit=True)['candidates'])

        client.request('open')

        assert '127.0.0.1/8' in client.request('execute', text='run show interfaces lo')['text']
    finally:
        client.close()


def test_real_unix_rpc_sessions_partial_commit_and_reconnect(daemon):
    alice, bob = Client(daemon), Client(daemon)

    try:
        alice.request("open")
        bob.request("open", draft=True)
        alice.request("execute", text="set interfaces dummy dum0 description LAN")
        alice.request("execute", text="set firewall ipv4 forward filter rule 10 description unfinished")
        alice.request("execute", text="commit")
        rendered = alice.request("execute", text="show running-configuration | commands")["text"]

        assert rendered == "set interfaces dummy dum0 description LAN\n"
        assert "rule 10 description unfinished" in alice.request("execute", text="compare | commands")["text"]
        assert bob.request("execute", text="show candidate-configuration")["text"].strip() == "{}"

        with pytest.raises(RouterError, match="Draft"):
            bob.request("execute", text="commit")
    finally:
        alice.close()
        bob.close()


def test_duplicate_notices_reach_cli_and_paste_continues(daemon):
    client = Client(daemon)
    outputs = []
    cli = CLI(client, emit=outputs.append)

    try:
        cli.submit('configure\nset interfaces dummy dum0 description "WAN Interface"\n'
                   'set interfaces dummy dum0 description "WAN Interface" disable\n'
                   'set interfaces dummy dum1 description next')

        assert ''.join(outputs) == (
            "Configuration already exists: set interfaces dummy dum0 description 'WAN Interface'\n")

        commands = client.request('execute', text='show candidate-configuration | commands')['text']

        assert 'set interfaces dummy dum0 disable' in commands
        assert 'set interfaces dummy dum1 description next' in commands

        cli.submit('commit')
        outputs.clear()
        cli.submit('set interfaces dummy dum0 disable')

        assert ''.join(outputs) == 'Configuration already exists: set interfaces dummy dum0 disable\n'
    finally:
        client.close()


def test_cli_paste_load_export_and_exit_confirmation(daemon, tmp_path):
    client = Client(daemon)
    outputs, questions = [], []
    cli = CLI(client, ask=lambda message: questions.append(message) or False, emit=outputs.append)

    try:
        cli.submit("configure\nset interfaces dummy dum0\nset broken bad\nset system host-name router")

        assert any("Line 3" in output for output in outputs)

        cli.submit("exit")

        assert cli.mode == "normal" and questions

        export = tmp_path / "proposal file.txt"
        cli.submit(f"compare | commands | export '{export}'")

        assert "set system host-name router" in export.read_text()

        cli.submit("discard")
        cli.submit(f"load set '{export}'")
        cli.submit("commit\nsave\nexit")

        assert cli.mode is None
    finally:
        client.close()


def test_rpc_bad_frame_and_session_isolation(daemon):
    client = Client(daemon)

    try:
        client.request("open")

        with pytest.raises(RouterError, match="already"):
            client.request("open")

        with pytest.raises(RouterError, match="not supported"):
            client.request("not-a-method", session="guessed-session-id")

        text = client.request("execute", text="run show version")["text"]

        assert text.startswith(" Version    | ") and "\n Build date | " in text
        assert len(text.splitlines()) == 5
    finally:
        client.close()

    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(str(daemon))
    connection.sendall(struct.pack("!I", MAX_FRAME + 1))
    connection.settimeout(2)

    assert connection.recv(1) == b""

    connection.close()


def test_incremental_frames_and_transport_eof_releases_lock(daemon):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(str(daemon))
    payload = encode({"version": VERSION, "id": 1, "operation": "open"})

    for byte in payload:
        connection.sendall(bytes([byte]))

    assert receive(connection)["done"]

    connection.close()
    second = Client(daemon)

    try:
        second.request("open")

        # request_lock refreshes liveness after EOF has been processed by the event loop.
        second.request("execute", text="request-session-lock")
    finally:
        second.close()


def test_bracketed_paste_waits_for_enter_and_tab_expands(daemon):
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import DummyHistory
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    async def scenario():
        client = Client(daemon)
        cli = CLI(client)
        cli.execute_line("configure")

        try:
            with create_pipe_input() as pipe:
                prompt = PromptSession(input=pipe, output=DummyOutput(), multiline=True,
                                       history=DummyHistory(), key_bindings=cli.bindings(),
                                       auto_suggest=TreeSuggestion(cli))
                pending = asyncio.create_task(prompt.prompt_async("test# "))
                pipe.send_text("\x1b[200~set interfaces dummy dum0\nset system host-name pasted\x1b[201~")
                await asyncio.sleep(.1)

                assert not pending.done()

                pipe.send_text("\r")
                text = await asyncio.wait_for(pending, 3)

                assert len(text.splitlines()) == 2

                cli.submit(text)
                pending = asyncio.create_task(prompt.prompt_async("test# "))
                pipe.send_text("set inter\t")
                await asyncio.sleep(.1)

                assert prompt.default_buffer.text == "set interfaces "

                pipe.send_text("dum dum1\r")

                assert (await asyncio.wait_for(pending, 3)).startswith("set interfaces dummy dum1")
        finally:
            client.close()

    asyncio.run(scenario())


def test_shell_preserves_connection_candidate_lock_and_edit(daemon, monkeypatch):
    client = Client(daemon)
    cli = CLI(client, emit=lambda _: None)
    launches = []

    def shell():
        launches.append(client.request('status'))

    monkeypatch.setattr('nvyr.cli.interactive_shell', shell)

    try:
        cli.submit('shell')

        assert cli.mode is None and launches[-1]['session'] is None

        cli.submit('configure\nset interfaces dummy dum0 description pending\nedit interfaces dummy dum0')
        identity, commit_id = cli.session_id, cli.commit_id
        cli.submit('shell')

        assert cli.mode == 'normal' and cli.session_id == identity and cli.commit_id == commit_id
        assert cli.edit == ['interfaces', 'dummy', 'dum0']
        assert launches[-1]['session'] == identity
        assert client.request('execute', text='show candidate-configuration | commands')['text'] == 'set description pending\n'

        cli.submit('commit')  # Lock ownership is preserved too.

        assert cli.commit_id == commit_id + 1

        cli.submit('exit\nconfigure draft\nshell')

        assert cli.mode == 'draft' and launches[-1]['session'] == cli.session_id
    finally:
        client.close()


def test_error_context_follows_submission_size(daemon, monkeypatch):
    from nvyr.errors import RouterError

    client = Client(daemon)
    output = []
    cli = CLI(client, emit=output.append)

    try:
        cli.submit('configure draft')

        for command in ['commit', 'compare missing', 'rollback missing', 'edit nonsense',
                        'show absent', 'load /definitely/missing', 'save', 'run missing']:
            output.clear()
            cli.submit(command)

            assert output and not any('Line 1:' in item or '\n  ' + command in item for item in output)

        monkeypatch.setattr('nvyr.cli.interactive_shell', lambda: (_ for _ in ()).throw(RouterError('Shell unavailable')))
        output.clear()
        cli.submit('shell')

        assert output == ['Shell unavailable']

        output.clear()
        cli.submit('set system host-name okay\nset firewall ipv4 forward filter rule 10 source-address 192.168.1.500/24\ncommit')

        assert any('Line 2:' in item and '^^^' in item for item in output)
        assert any('Line 3:' in item and 'Draft sessions' in item for item in output)
    finally:
        client.close()


def test_firewall_commit_result_reaches_cli_and_defaults_stay_implicit(daemon):
    import json

    client = Client(daemon)
    outputs = []
    cli = CLI(client, emit=outputs.append)

    try:
        cli.submit('configure\nset interfaces dummy dum0 address 1.1.1.1/32\nset firewall ipv4 forward filter rule 10 action accept\nset firewall ipv4 forward filter rule 10 log\ncommit')
        rendered = ''.join(outputs)

        assert 'firewall: done\n' in rendered
        assert 'dummy: done\n' in rendered
        assert 'Commit 1 completed in ' in rendered and cli.commit_id == 1

        running = json.loads(client.request('execute', text='show running-configuration firewall')['text'])

        assert 'default-action' not in running['ipv4']['forward']['filter']
        assert client.request('execute', text='show candidate-configuration')['text'] == '{}\n'
    finally:
        client.close()


def test_scoped_configuration_commands_through_rpc(daemon):
    client = Client(daemon)

    try:
        client.request('open')
        client.request('execute', text='set interfaces dummy dum0 address 150.0.0.1/32')
        client.request('execute', text='set system host-name outside')
        client.request('execute', text='commit')

        assert client.request('execute', text='show running-configuration interfaces | commands')['text'] == (
            'set dummy dum0 address 150.0.0.1/32\n')

        client.request('execute', text='edit interfaces')
        client.request('execute', text='edit dummy dum0')

        assert client.request('execute', text='show running-configuration | commands')['text'] == (
            'set address 150.0.0.1/32\n')

        client.request('execute', text='set description "Pending description"')

        assert client.request('execute', text='show candidate-configuration | commands')['text'] == (
            "set description 'Pending description'\n")

        client.request('execute', text='top')

        assert client.request('execute', text='show candidate-configuration | commands')['text'] == (
            "set interfaces dummy dum0 description 'Pending description'\n")
    finally:
        client.close()


def test_large_output_streams_bounded_chunks_without_client_snapshot(daemon):
    client = Client(daemon)

    try:
        client.request("open")
        content = "\n".join(f"set interfaces dummy dum{i} description '{'x' * 60}'" for i in range(700))

        assert not client.request("load", content=content, set_format=True)["errors"]

        chunks = []
        client.request("execute", text="compare | commands", on_text=chunks.append)

        assert len(chunks) > 1
        assert all(len(chunk) <= 32768 for chunk in chunks)
        assert "dum699" in "".join(chunks)
        assert set(vars(client)) == {"socket", "counter", "_request_lock"}
    finally:
        client.close()


def test_edit_context_printed_after_commands_blank_returns_and_errors(daemon):
    client = Client(daemon)
    output = []
    cli = CLI(client, emit=output.append)

    try:
        cli.submit("configure\nedit interfaces dummy dum0")

        assert output[-1] == "[edit interfaces dummy dum0]"

        cli.submit('set description "Test Interface"')

        assert output[-1] == "[edit interfaces dummy dum0]"

        count = len(output)
        cli.submit("")

        assert output[count:] == ["[edit interfaces dummy dum0]"]

        cli.submit("set bad-setting value")

        assert "Unknown command or setting" in output[-2]
        assert output[-1] == "[edit interfaces dummy dum0]"

        cli.submit("up")

        assert output[-1] == "[edit interfaces]"

        count = len(output)
        cli.submit("top")

        assert len(output) == count
    finally:
        client.close()


def test_declining_commit_confirm_preserves_pending_changes(daemon):
    import json

    client = Client(daemon)
    questions, output = [], []
    cli = CLI(client, ask=lambda message: questions.append(message) or False, emit=output.append)

    try:
        cli.submit("configure\nset system host-name pending\ncommit-confirm 10")

        assert len(questions) == 1 and "automatic rollback in 10 minutes?" in questions[0]
        assert "confirm_minutes" not in questions[0]
        assert json.loads(client.request("execute", text="show running-configuration")["text"]) == {}
        assert "pending" in client.request("execute", text="show candidate-configuration")["text"]

        cli.ask = lambda message: True
        cli.submit("commit-confirm 10\nconfirm")

        assert cli.commit_id == 1
        assert "pending" in client.request("execute", text="show running-configuration")["text"]
    finally:
        client.close()


def test_stale_and_commit_confirm_prompts_accumulate_without_looping(daemon):
    first, second = Client(daemon), Client(daemon)
    questions = []

    try:
        first_session = first.request("open")
        cli = CLI(second, ask=lambda message: questions.append(message) or True, emit=lambda _: None)
        cli.submit("configure\nset system host-name second")
        first.request("execute", text="set system host-name first")
        first.request("execute", text="commit")
        second.request("execute", text="request-session-lock", confirmation={"session": first_session["session"]})
        cli.submit("commit-confirm 10")

        assert len(questions) == 2
        assert "changed to commit 1" in questions[0] and "automatic rollback" in questions[1]
        assert cli.commit_id == 2

        cli.submit("confirm")
    finally:
        first.close()
        second.close()


def test_history_up_down_mode_isolation_and_no_prediction_from_history(daemon):
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput
    from prompt_toolkit.document import Document

    async def scenario():
        client = Client(daemon)
        cli = CLI(client, ask=lambda _: True, emit=lambda _: None)

        try:
            cli.submit("show version\nconfigure\nset system host-name router\ndiscard\nexit")

            assert cli.histories["operational"].get_strings() == ["show version", "configure"]
            assert cli.histories["configuration"].get_strings() == ["set system host-name router", "discard", "exit"]

            with create_pipe_input() as pipe:
                prompts = cli.make_prompts(input=pipe, output=DummyOutput())
                prompt = prompts["operational"]
                pending = asyncio.create_task(prompt.prompt_async("op> "))

                for keys, expected in [("\x1b[A", "configure"), ("\x1b[A", "show version"), ("\x1b[B", "configure"), ("\x1b[B", "")]:
                    pipe.send_text(keys)
                    await asyncio.sleep(.04)

                    assert prompt.default_buffer.text == expected

                pipe.send_text("\x1b[A\r")
                cli.submit(await asyncio.wait_for(pending, 3))

                assert cli.mode == "normal"

                prompt = prompts["configuration"]
                pending = asyncio.create_task(prompt.prompt_async("configuration# "))
                pipe.send_text("\x1b[A")
                await asyncio.sleep(.04)

                assert prompt.default_buffer.text == "exit"

                pipe.send_text("\r")
                cli.submit(await asyncio.wait_for(pending, 3))

                assert cli.mode is None

            cli.execute_line("show phantom-history-only")

            assert "show phantom-history-only" in cli.histories["operational"].get_strings()
            assert TreeSuggestion(cli).get_suggestion(None, Document("show pha")) is None
            assert client.request("complete", text="show pha", explicit=True)["candidates"] == []
        finally:
            client.close()

    asyncio.run(scenario())


def test_idle_rollback_notification_preserves_prompt_and_synchronizes_id(daemon):
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    async def scenario():
        client = Client(daemon)
        output, questions = [], []
        cli = CLI(client, ask=lambda message: questions.append(message) or True, emit=output.append)

        try:
            cli.submit("configure\nset system host-name temporary\ncommit-confirm 0.01")

            assert cli.commit_id == 1

            with create_pipe_input() as pipe:
                prompt = cli.make_prompts(input=pipe, output=DummyOutput())["configuration"]
                pending = asyncio.create_task(prompt.prompt_async("router# ", pre_run=lambda: prompt.app.create_background_task(cli.watch_notifications(.025))))
                pipe.send_text("set system host-name permanent")
                deadline = time.monotonic() + 5

                while not any("timer expired" in message for message in output):
                    assert time.monotonic() < deadline

                    await asyncio.sleep(.025)

                assert not pending.done()
                assert prompt.default_buffer.text == "set system host-name permanent"
                assert cli.commit_id == 2

                pipe.send_text("\r")
                cli.submit(await asyncio.wait_for(pending, 3))
                cli.submit("commit")

                assert cli.commit_id == 3 and len(questions) == 1

                cli.receive_status(client.request("status", after=cli.event_cursor))

                assert sum("timer expired" in message for message in output) == 1
        finally:
            client.close()

    asyncio.run(scenario())


def test_compare_empty_tab_lists_saved_and_history_without_inserting_saved(daemon, monkeypatch):
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    async def scenario():
        client = Client(daemon)
        cli = CLI(client, emit=lambda _: None)
        displayed = []
        monkeypatch.setattr("nvyr.cli.print_formatted_text", displayed.append)

        try:
            cli.submit("configure\nset system host-name router\ncommit")

            with create_pipe_input() as pipe:
                prompt = cli.make_prompts(input=pipe, output=DummyOutput())["configuration"]
                pending = asyncio.create_task(prompt.prompt_async("router# "))

                # Bracketed paste avoids Space expanding the optional saved argument.
                pipe.send_text("\x1b[200~compare \x1b[201~\t")
                deadline = time.monotonic() + 3

                while not displayed:
                    assert time.monotonic() < deadline

                    await asyncio.sleep(.025)

                assert prompt.default_buffer.text == "compare "
                assert "Saved configuration" in displayed[-1] and displayed[-1].count("UTC") == 2

                pipe.send_text("\r")
                await asyncio.wait_for(pending, 3)
        finally:
            client.close()

    asyncio.run(scenario())


@pytest.mark.parametrize('daemon', [{'kind': 'node', 'children': {'probe': {
    'kind': 'node', 'anchor': True,
    'command': {'stream': True, 'argv': [sys.executable, '-c',
        'from nvyr import opmode\n'
        '@opmode.command\n'
        'def show(line):\n'
        '    print("PROBE", line, flush=True)\n'
        '    raise SystemExit(7)\n'
        'opmode.run()\n', 'show', '@line']},
    'children': {'count': {'kind': 'leaf_node'},
                 'numeric': {'kind': 'leaf_node', 'valueless': True}}
}}}], indirect=True)
def test_anchored_streaming_roundtrip_preserves_rpc_session(daemon, capfd):
    client = Client(daemon)

    try:
        event = client.request('execute', text='probe numeric count 2')

        assert event['event'] == 'command' and event['returncode'] == 7
        assert 'argv' not in event and event['text'] == 'PROBE probe numeric count 2\r\n'

        output = []
        cli = CLI(client, emit=output.append)
        cli.execute_line('probe count 2 numeric')

        assert not capfd.readouterr().out
        assert cli.returncode == 7 and ''.join(output) == 'PROBE probe count 2 numeric\r\n'
        assert 'commit_id' in client.request('status')

        opened = client.request('open')
        cli.mode = 'normal'
        cli.execute_line('run probe numeric count 3')

        assert 'PROBE run probe numeric count 3\r\n' in ''.join(output)
        assert client.request('status')['session'] == opened['session']
        assert client.request('execute', text='show candidate-configuration | commands').get('text', '') == ''
    finally:
        client.close()

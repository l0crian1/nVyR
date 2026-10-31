"""Human presentation of configd's commit results and session status."""

from datetime import datetime, timezone
import math

from tabulate import tabulate


def duration(seconds):
    seconds = max(0, math.ceil(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    return f'{hours:02d}:{minutes:02d}:{seconds:02d}'


def deadline(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def commit_history(commit_id, records):
    rows = [(commit_id - record['id'], record['id'], deadline(record['timestamp']),
             record['user'], record['comment'] or '') for record in records]

    return tabulate(rows, headers=['Revision', 'Commit', 'Date', 'User', 'Comment'],
                    disable_numparse=[3, 4]) + '\n'


def report_text(message):
    return str(message).rstrip('\n') + '\n'


def commit_progress(schema, event, owner, value):
    name = owner
    if event == 'start':
        return f'Applying {name}...\n'

    if event == 'report':
        return report_text(value)

    if value['success']:
        return f'{name}: done\n\n'

    return f"{name}: failed — {value['error']}\n\n"


def commit_summary(schema, result):
    if not result['results']:
        return 'No configuration changes to commit.\n'

    failed = [owner for owner, row in result['results'].items() if not row['success']]
    succeeded = sum(row['success'] for row in result['results'].values())
    elapsed = result['elapsed']
    if failed:
        text = f'Commit partially completed in {elapsed:.2f}s.' if succeeded else f'Commit failed after {elapsed:.2f}s.'
        text += f' {succeeded} applied, {len(failed)} failed.\n'
        text += 'Changes remain pending: ' + ', '.join(failed) + '.\n'
    else:
        text = f"Commit {result['commit_id']} completed in {elapsed:.2f}s.\n"

    if result.get('deadline') is not None:
        text += f"Confirm before {deadline(result['deadline'])} to prevent automatic rollback.\n"
    elif result['changed']:
        text += 'Running configuration has changed. Use save to persist it across reboots.\n'

    return text


def identity(value, current):
    marker = ' (this session)' if value['session'] == current else ''
    details = f"{value['user']} on {value['vty']} — " if 'user' in value else ''

    return details + value['session'] + marker


def scheduled_commit(scheduled):
    if scheduled is None:
        return 'No configuration changes to schedule.\n'

    text = f"Commit scheduled for {deadline(scheduled['when'])}.\n"
    if scheduled['confirm_minutes'] is not None:
        text += f"Automatic rollback: {scheduled['confirm_minutes']:g} minutes after the commit completes.\n"
    text += 'The scheduled candidate is frozen. Use cancel to cancel before it starts.\n'
    return text


def configuration_status(schema, status):
    current = status['session']['session']
    activity = status['activity']
    if activity:
        state = activity['operation'].capitalize()
        if activity['owner']:
            state += ': ' + activity['owner']

        state += f" ({activity['elapsed']:.2f}s)"
        if activity['session']:
            state += ' — ' + identity(activity['session'], current)
    else:
        state = 'Idle'

    confirm = 'None'
    if status['deadline'] is not None:
        confirm = f"{deadline(status['deadline'])} ({duration(status['confirm_remaining'])} remaining)"

    scheduled = status.get('scheduled')
    schedule = 'None'
    if scheduled:
        schedule = f"{deadline(scheduled['when'])} ({duration(scheduled['remaining'])} remaining)"
        schedule += ' — ' + identity(scheduled['session'], current)
        if scheduled['confirm_minutes'] is not None:
            schedule += f"; confirm within {scheduled['confirm_minutes']:g} minutes after completion"

    rows = [
        ('Session', current + ' (this session)'),
        ('Session type', 'Draft' if status['draft'] else 'Normal'),
        ('Session remaining', duration(status['remaining'])),
        ('Running commit', status['commit_id']),
        ('Candidate changes', ', '.join(status['changed']) or 'None'),
        ('Unsaved running changes', 'Yes' if status['unsaved'] else 'No'),
        ('Commit-confirm deadline', confirm),
        ('Scheduled commit', schedule),
        ('Activity', state),
        ('Commit lock', identity(status['lock'], current) if status['lock'] else 'Available'),
        ('Recovery required', 'Yes' if status['unhealthy'] else 'No'),
    ]

    return tabulate(rows, tablefmt='presto') + '\n'

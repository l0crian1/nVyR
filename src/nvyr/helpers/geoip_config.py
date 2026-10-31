"""Pure configuration checks for DB-IP Country Lite address groups."""

from nvyr.errors import ValidationError
from nvyr.tree import lookup


# ISO 3166-1 alpha-2, plus DB-IP's Kosovo and unlocated/reserved codes.
COUNTRIES = frozenset('''
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS
MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS
RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW
TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW ZZ
'''.split())


def groups(configuration):
    result = {}
    for family, definitions in lookup(configuration, ('firewall', 'group', 'address-group'), {}).items():
        for name, definition in definitions.items():
            if 'geoip' in definition:
                result[family, name] = tuple(sorted(definition['geoip'].get('country', ())))
    return result


def verify(family, name, definition):
    # Ordinary groups do not use externally maintained membership.
    if 'geoip' not in definition:
        return

    path = f'firewall group address-group {family} {name}'
    countries = definition['geoip'].get('country', ())
    # An empty selector must not install an unintentionally empty policy set.
    if not countries:
        raise ValidationError(f'{path}: geoip requires at least one country')
    # Verify programmatic input too; only DB-IP's supported codes are meaningful.
    if not set(countries) <= COUNTRIES:
        raise ValidationError(f'{path}: invalid GeoIP country code')
    # One source owns membership, so refreshing it cannot erase manual policy.
    if definition.get('address') or 'dynamic' in definition:
        raise ValidationError(f'{path}: geoip cannot be combined with address or dynamic')

from rolepermissions.roles import AbstractUserRole

from reNgine.definitions import (
    PERM_INITATE_SCANS_SUBSCANS,
    PERM_MODIFY_INTERESTING_LOOKUP,
    PERM_MODIFY_SCAN_CONFIGURATIONS,
    PERM_MODIFY_SCAN_REPORT,
    PERM_MODIFY_SCAN_RESULTS,
    PERM_MODIFY_SYSTEM_CONFIGURATIONS,
    PERM_MODIFY_TARGETS,
    PERM_MODIFY_WORDLISTS,
)


class SysAdmin(AbstractUserRole):
    available_permissions = {
        PERM_MODIFY_SYSTEM_CONFIGURATIONS: True,
        PERM_MODIFY_SCAN_CONFIGURATIONS: True,
        PERM_MODIFY_SCAN_RESULTS: True,
        PERM_MODIFY_WORDLISTS: True,
        PERM_MODIFY_INTERESTING_LOOKUP: True,
        PERM_MODIFY_SCAN_REPORT: True,
        PERM_INITATE_SCANS_SUBSCANS: True,
        PERM_MODIFY_TARGETS: True,
    }


class PenetrationTester(AbstractUserRole):
    available_permissions = {
        PERM_MODIFY_SYSTEM_CONFIGURATIONS: False,
        PERM_MODIFY_SCAN_CONFIGURATIONS: True,
        PERM_MODIFY_SCAN_RESULTS: True,
        PERM_MODIFY_WORDLISTS: True,
        PERM_MODIFY_INTERESTING_LOOKUP: True,
        PERM_MODIFY_SCAN_REPORT: True,
        PERM_INITATE_SCANS_SUBSCANS: True,
        PERM_MODIFY_TARGETS: True,
    }


class Auditor(AbstractUserRole):
    available_permissions = {
        PERM_MODIFY_SYSTEM_CONFIGURATIONS: False,
        PERM_MODIFY_SCAN_CONFIGURATIONS: False,
        PERM_MODIFY_SCAN_RESULTS: True,
        PERM_MODIFY_WORDLISTS: False,
        PERM_MODIFY_INTERESTING_LOOKUP: True,
        PERM_MODIFY_SCAN_REPORT: True,
        PERM_INITATE_SCANS_SUBSCANS: False,
        PERM_MODIFY_TARGETS: False,
    }

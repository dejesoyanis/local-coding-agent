# LCA-ARCH-29: Separate Windows principal and credential boundary

- Status: Accepted
- Decision: **C. Cross-identity boundary not established.** The harness can describe a worker principal and can refuse a same-user SID, but no worker process was started under a different user SID. Command execution stays disabled. The production publisher stays `apply_ntfs`.
- Milestone: LCA-01N

## Contract

`PrincipalSnapshot` is filled from a Windows token handle: user SID, logon SID, token type, integrity, enabled groups, restricted groups, privileges, authentication id, and token source. `Verification` records how that snapshot was obtained.

| State | Meaning |
| --- | --- |
| `Unverified` | Nothing was read. |
| `SidOnly` | A SID string was compared. No token handle was read. |
| `TokenObserved` | `GetTokenInformation` was called on a token handle. |
| `AccessChecked` | The token was read and an access measurement was recorded for that process. |
| `Rejected` | The snapshot was refused. |

A worker message cannot produce `TokenObserved` or `AccessChecked`. `INV-11` treats a boundary claim that rests on `SidOnly` as a violation.

## Invariants

| Id | Rule | This run |
| --- | --- | --- |
| INV-01 | Worker user SID differs from the broker user SID, and both were read from tokens. | Contract rejects a same SID. No second token was read. |
| INV-02 | The worker is not in a privileged group and is not above medium integrity. | Contract rejects Administrators, domain admin RIDs, and high integrity. |
| INV-03 | The worker token does not contain a dangerous privilege, even if that privilege is disabled. | Contract rejects `SeDebugPrivilege` and the other named privileges. |
| INV-04 | The worker cannot open the test store, recovery evidence, or restoration evidence. | Not run against another principal. |
| INV-05 | The worker cannot open the protected host fixtures. | Not run against another principal. |
| INV-06 | Only `ping`, `worker_info`, and `read_fixture` are registered. | Unit-tested. |
| INV-07 | A path-shaped resource id is not authorization. | Unit-tested. |
| INV-08 | Handles are not inherited unless they are in the explicit list. | The launch contract rejects `inherit_unlisted`. |
| INV-09 | A restart is a new session id and a new logon id. | Contract-tested. A second logon was not created. |
| INV-10 | Broker abort ends the worker. | The predicate is tested. No cross-identity process was alive to kill. |
| INV-11 | A different SID string is not isolation. | A `SidOnly` claim is a violation. |
| INV-12 | The worker cannot insert a grant. | `approve` is denied and the grant map is unchanged. |

## What Windows did in this run

The broker process token, read with `GetTokenInformation`:

| Field | Measured |
| --- | --- |
| SID | well-formed, length 46. The value is not copied into this record. |
| Logon SID | present |
| Token type | primary (`1`) |
| Integrity | medium |
| Enabled groups | 11 |
| Restricted groups | 0 |
| Privileges | 5, none on the dangerous list |
| Authentication id | non-zero |
| Token source | non-empty (5 bytes) |
| Verification | `TokenObserved` |
| Administrators membership | `admin=0` |

`AccessCheck` against an in-memory descriptor that grants `FILE_READ_DATA` only to `S-1-5-21-1-2-3-99` denied the broker token (`foreign_denied=1`). The same check with an ACE for the broker user allowed it (`self_allowed=1`). The descriptor's owner and group were set; without them `AccessCheck` returned `1338`. A temporary file locked to the current user and SYSTEM had `owner_match=1` and `ace_count=2`. That file was removed. No production ACL was edited.

The current user created a hard link to a file it owns (`same_user_hardlink=0`). That is the opposite of isolation.

## API semantics and what was not called

| API | Documented behavior | This milestone |
| --- | --- | --- |
| `GetTokenInformation` | Returns the token's user, groups, privileges, statistics, and source. | Used on the current process. |
| `AccessCheck` | Evaluates a descriptor against an impersonation token. A SID string is not an input. | Used. Owner and group were required for a valid descriptor. |
| `CheckTokenMembership` | Reports membership of the supplied token. | Administrators membership was `0`. |
| `GetNamedSecurityInfoW` | Reads the owner and DACL of a named object. | Used on the temporary file. |
| `LookupAccountNameW` | Resolves an account name to a SID. It does not log on. | Not called. `LCA_01N_ACCOUNT` was unset. |
| `LogonUserW` | Returns a token for the named user. The password is an API argument. | Not called. |
| `CreateProcessWithLogonW` | Starts a process as that user. The password is not part of the command line. It does not accept `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. | Not called. |
| `CreateProcessAsUserW` | Assigns a primary token. The caller normally needs `SeAssignPrimaryTokenPrivilege`. | Not called. The privilege was not enabled. |
| `DuplicateTokenEx` | Makes an impersonation token for `AccessCheck`. | Used on the current token. |
| `CreateRestrictedToken` | Still the same user. Measured in [LCA-ARCH-26](LCA-ARCH-26.md). | Not repeated as a cross-identity result. |

## Credential boundary

The account name is `LCA_01N_ACCOUNT`. It is a local SAM name, not a password. The secret, when a person has stored one, is a Windows Credential Manager generic credential whose target is `LCA-01N-Worker`. The harness reads it with `CredReadW` and passes it only to `LogonUserW` and `CreateProcessWithLogonW`. `Debug` of the buffer prints `redacted`. The buffer is cleared on drop.

This run did not read the credential. The report was:

`INCONCLUSIVE reason=account_not_configured code=0 gate=C worker_started=0 account_created=0 logon_attempted=0`

No account was created, changed, or deleted. No password was written to the repository, the command line builder, the environment builder, or the report. The environment builder rejects a key that contains `PASSWORD`, `SECRET`, `PWD`, `TOKEN`, or `CRED`.

## What is not claimed

- That the broker token above is a worker sandbox. It is the interactive user.
- That `admin=0` or five ordinary privileges confine that user.
- That a hard link the current user can create would fail for a different user. That was not run.
- That `CreateProcessWithLogonW` will succeed once a credential exists. Profile load, executable ACL, and window station were not exercised.

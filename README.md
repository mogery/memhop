# memhop
Cross-platform memory reader

## Platform support

| **Platform** | **Supported?** | **Mechanism(s)** | **Notes** |
|--------------|----------------|------------------|-----------|
| Linux        | **yes**        | procfs           |           |
| Windows      | **yes**        | winapi           |           |
| macOS        | **yes**        | mach + libproc   |           |
| \*BSD        | *not yet*      | ptrace PT_IO     |           |
| Android      | *not yet*      | procfs?          |           |
| iOS & deriv. | *not yet*      | mach + libproc   | Code should be same as for macOS, needs testing. |
| Fuchsia      | *not yet*      | ?                | No clue how Fuchsia works, help needed. |
| Redox        | *not yet*      | ?                | No clue how Redox works, help needed.   |

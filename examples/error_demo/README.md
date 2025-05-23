# Custom Error Codes in Hopper

This document explains how to define custom error codes in Hopper custom rule files.

## Defining Error Codes

Error codes can be defined in the `custom.rule` file using the `err` keyword:

```
err <value> ["description"]
```

Where:

- `<value>` is an integer error code value (positive or negative)
- `["description"]` is an optional description of the error code in quotes

## Examples

```
// Basic error codes
err -1 "Operation failed"
err -2 "Invalid argument"

// System error codes
err -22 "Invalid argument (EINVAL)"
err -13 "Permission denied (EACCES)"

// Library-specific error codes
err 1 "Success with warning"
err -100 "Custom error"
```

## How Error Codes Are Used

When Hopper generates test programs, it will check function return values against these error codes to detect graceful failures. Instead of hardcoding a specific error value like `-2`, Hopper will randomly select from the defined error codes.

This allows Hopper to understand what error values are meaningful for your library and use them appropriately in tests.

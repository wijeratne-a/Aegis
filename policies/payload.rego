# Request-level payload policy for Aegis proxy (A2T/A2A/A2D).
# Evaluates decrypted HTTP request: method, path, host, body, headers, identity.
package aegis.payload

default allow = true
default reason = ""

# Deny if body.text matches SSN-like pattern (A2T).
allow = false {
  body := input.body
  body != null
  body.text != null
  regex.match("[0-9]{3}-[0-9]{2}-[0-9]{4}", body.text)
}
reason = "body contains SSN-like pattern" {
  body := input.body
  body != null
  body.text != null
  regex.match("[0-9]{3}-[0-9]{2}-[0-9]{4}", body.text)
}

# Deny if GraphQL mutation delete and identity suggests read-only (A2D).
allow = false {
  body := input.body
  body != null
  body.query != null
  contains(body.query, "mutation { delete_")
  input.identity.iam_role == "ReadOnly"
}
reason = "GraphQL delete mutation not allowed for ReadOnly role" {
  body := input.body
  body != null
  body.query != null
  contains(body.query, "mutation { delete_")
  input.identity.iam_role == "ReadOnly"
}

# A2A: when x-aegis-caller is present (agent-to-agent), require x-aegis-trace for audit chain.
allow = false {
  caller := input.headers["x-aegis-caller"]
  caller != null
  caller != ""
  trace := input.headers["x-aegis-trace"]
  trace == null
}
reason = "A2A call requires x-aegis-trace header" {
  caller := input.headers["x-aegis-caller"]
  caller != null
  caller != ""
  trace := input.headers["x-aegis-trace"]
  trace == null
}

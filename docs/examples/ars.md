---
title: ARS examples
description: Access Request Service (ARS) command examples
---

# Access Request Service (ARS) examples

### List the request form of VM dual control access requests
```shell linenums="0"
idsec exec ars requests list-request-forms --target-category VM --request-type DUAL_CONTROL
```

### List the request form of cloud console on demand access requests
```shell linenums="0"
idsec exec ars requests list-request-forms --target-category CLOUD_CONSOLE
```

### List the request form of group dual control access requests
```shell linenums="0"
idsec exec ars requests list-request-forms --target-category GROUP --request-type DUAL_CONTROL
```

### Submit a VM dual control access request and wait until it is pending approval
The request details are provided in a request file, for example:
```json
{"requestDetails": {"targetType": "Linux", "targetAddress": "myvm.mydomain.com", "reason": "Maintenance", "requestDate": "2026-12-01", "requestEndDate": "2026-12-02", "timeFrom": "08:00", "timeTo": "17:00", "timezone": "GMT", "priority": "High"}}
```

<!-- idsec-example: skip reason="reads a placeholder request file" -->
```shell linenums="0"
idsec exec --request-file /path/to/access-request.json ars requests submit --target-category VM --request-type DUAL_CONTROL --poll
```

### Submit an access request and wait until it finishes
<!-- idsec-example: skip reason="reads a placeholder request file" -->
```shell linenums="0"
idsec exec --request-file /path/to/access-request.json ars requests submit --target-category VM --request-type DUAL_CONTROL --poll --wait-until-finished
```

### List all access requests
```shell linenums="0"
idsec exec ars requests list
```

### List extended access requests, newest first
```shell linenums="0"
idsec exec ars requests list-by --extended --sort '[{"field": "createdAt", "direction": "desc"}]'
```

### List access requests with a page limit and offset
```shell linenums="0"
idsec exec ars requests list-by --limit 50 --offset 100
```

### Get an access request
```shell linenums="0"
idsec exec ars requests get --request-id my-request-id
```

### Show access requests statistics
```shell linenums="0"
idsec exec ars requests stats
```

### Cancel an access request and wait until it finishes
```shell linenums="0"
idsec exec ars requests cancel --request-id my-request-id --cancel-reason "No longer needed" --poll
```

### Approve an access request
```shell linenums="0"
idsec exec ars requests finalize --request-id my-request-id --result APPROVED
```

### Reject an access request with a reason, and wait until it finishes
```shell linenums="0"
idsec exec ars requests finalize --request-id my-request-id --result REJECTED --finalization-reason "Not allowed" --poll --wait-until-finished
```

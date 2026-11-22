---
title: Session Monitoring examples
description: Session Monitoring command examples
---

# Session Monitoring examples

## Sessions

### List sessions
```shell linenums="0"
idsec sm sessions list
```

### Count sessions
```shell linenums="0"
idsec sm sessions count
```

### List sessions by filter
```shell linenums="0"
idsec sm sessions list-by --search "duration LE 01:00:00"
```

### Count sessions by filter
```shell linenums="0"
idsec sm sessions count-by --search "command STARTSWITH ls"
```

### Get a session
```shell linenums="0"
idsec sm sessions get --session-id my-id
```

### Get sessions statistics
```shell linenums="0"
idsec sm sessions stats
```

## Session Activities

### List session activities
```shell linenums="0"
idsec sm session-activities list --session-id my-id
```

### Count session activities
```shell linenums="0"
idsec sm session-activities count --session-id my-id
```

### List session activities by filter
```shell linenums="0"
idsec sm session-activities list-by --session-id my-id --command-contains "ls"
```

### Count session activities by filter
```shell linenums="0"
idsec sm session-activities count-by --session-id my-id --command-contains "chmod"
```

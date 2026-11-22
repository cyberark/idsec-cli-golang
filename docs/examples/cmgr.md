---
title: CMGR examples
description: Connector Manager command examples
---

# CMGR examples

### List CMGR connector pools
```shell linenums="0"
idsec cmgr pools list
```

### Add CMGR network
```shell linenums="0"
idsec cmgr networks create --name mynetwork
```

### Add CMGR connector pool
```shell linenums="0"
idsec cmgr pools create --name mypool --assigned-network-ids mynetwork_id
```

# Vulners Ansible Plugin - Test Env

To test plugin, you can start __vulnerable__ Alpine-Linux container.

Container will expose port 2222 on you local machine with installed ssh pub key.

## Start vulnerable Alpine container

To allow Ansible access server with your ssh key, add id_rsa.pub to authorized_keys
```bash
cat ~/.ssh/id_rsa.pub > ./test/ssh/authorized_keys
```
Start server

```bash
docker compose up
```

To check host available and open for SSH connection
```shell
ssh test@127.0.0.1 -p2222
```
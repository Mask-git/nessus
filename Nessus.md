```
docker run -itd --name=paster_nessus -p 8834:8834 42hao/paster
https://hub.docker.com/repository/docker/42hao/paster/general
```

如果忘记密码的话

```
docker exec -it paster_nessus bash
cd  /opt/nessus/sbin
./nessuscli lsuser
./nessuscli chpasswd admin
```

不得用于商业 仅供学习交流使用

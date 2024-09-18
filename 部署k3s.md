```shell
# 部署指定版本的k3s，使用阿里云进行加速安装
$ curl -sfL https://rancher-mirror.rancher.cn/k3s/k3s-install.sh | INSTALL_K3S_MIRROR=cn INSTALL_K3S_CHANNEL=v1.27 sh -s - --system-default-registry "registry.cn-hangzhou.aliyuncs.com"
$ systemctl status k3s

```

<h2 id="fxY43">k3s扩充节点</h2>
```shell
# 主节点查看token值
$ cat /var/lib/rancher/k3s/server/node-token
# 从节点去执行命令，加入到集群  | 这里把ip和token加上去就可以了
$ curl -sfL https://rancher-mirror.rancher.cn/k3s/k3s-install.sh | INSTALL_K3S_MIRROR=cn K3S_URL=https://myserver:6443 K3S_TOKEN=mynodetoken sh -
# 主节点查看
$ kubectl get nodes
```

<h2 id="X1PKW">部署rancher-管理工具</h2>
我采用的离线部署rancher，rancher的版本是stable对应的应该是v2.9.1

```shell
$ docker run --privileged -d --restart=unless-stopped -p 80:80 -p 443:443 rancher/rancher:stable

# 查看容器的状态
$ docker ps
```

浏览器访问https://ip

![](https://cdn.nlark.com/yuque/0/2024/jpeg/47684456/1726623657013-e4296e17-1595-4e49-b5dc-8b30cf3029eb.jpeg)

```shell
# 找出来rancher的容器ID
$ docker

# 查看rancher的日志，过滤出来登录密码
$ docker logs  9aa7ccc67a2e  2>&1 | grep "Bootstrap Password:"
```

这里选择第二个选项自己设置密码，然后登陆即可

![](https://cdn.nlark.com/yuque/0/2024/jpeg/47684456/1726623946549-0f28d233-af93-433e-93cc-2ceb4242a03d.jpeg)

<h3 id="NSJvG">rancher切换中文</h3>
退出登录，在登陆页面左下角即可切换中文

![](https://cdn.nlark.com/yuque/0/2024/jpeg/47684456/1726624137414-96d71d91-0896-4da2-8c20-61ad2d6c0403.jpeg)![](https://cdn.nlark.com/yuque/0/2024/jpeg/47684456/1726624137453-1e09061e-4e84-466b-bf07-150d77d08beb.jpeg)

<h3 id="NpPiV">rancher导入k3s集群</h3>
具体操作如下

![](https://cdn.nlark.com/yuque/0/2024/jpeg/47684456/1726624395833-cd4a0311-65f5-444f-8eae-68f4c53fbf15.jpeg)

![](https://cdn.nlark.com/yuque/0/2024/jpeg/47684456/1726624441057-a1e06e52-9f52-4b51-b5aa-300d87fcc4ab.jpeg)![](https://cdn.nlark.com/yuque/0/2024/jpeg/47684456/1726624441094-c9d026a5-df0a-422b-a265-c8f8f527d37c.jpeg)![](https://cdn.nlark.com/yuque/0/2024/jpeg/47684456/1726624441123-2de4b855-332d-41fe-b654-db00dc43a695.jpeg)

```shell
# 在导入集群的时候有一个小小的改动 具体命令如下
$ curl --insecure -sfL https://172.16.90.30/v3/import/st4jnrn6zjbtmbn7g48h7lv5m8b7c4dmd9tnv5gdbch4b98vb8n7cq_c-m-w87qckn8.yaml > a.yaml

# 修改yaml文件内镜像地址为自己的
$ image: registry.cn-hangzhou.aliyuncs.com/yangqianjing/rancher-agent:v2.9.1

# 保存退出执行
$ kubectl apply -f a.yaml

# 查看pod的状态是否已经创建成功
$ kubectl get pods -n cattle-system

```

查看导入集群的状态

![](https://cdn.nlark.com/yuque/0/2024/jpeg/47684456/1726625902619-e946b9ca-2019-4f47-a756-044e5ab68c3d.jpeg)

<h3 id="WCZBb">rancher导入集群目前遇到的一个问题</h3>
问题描述：<font style="color:#DF2A3F;">pod创建成功之后会自动又创建了一个pod，且这个pod是到docker hub中去拉取镜像，没有到我指定的仓库里面拉取镜像</font>

解决办法如下:

```shell
# 进入到这个pod的yaml文件内
[root@idm-demo01 ~]# kubectl get pods -n cattle-system
NAME                                    READY   STATUS             RESTARTS   AGE
cattle-cluster-agent-7957bb4b68-h6w2l   1/1     Running            0          8m15s
cattle-cluster-agent-7cb95f866c-9c62n   0/1     ImagePullBackOff   0          4m31s
[root@idm-demo01 ~]# kubectl edit pod cattle-cluster-agent-7cb95f866c-9c62n -n cattle-system

# 把镜像仓库修改成自己的
$ image: registry.cn-hangzhou.aliyuncs.com/yangqianjing/rancher-agent:v2.9.1

# 再次查询pod的状态，其他pod也出现了这种问题，我就直接如法炮制了
```


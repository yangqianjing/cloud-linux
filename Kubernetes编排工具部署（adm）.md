#  Kubernetes容器编排adm部署一主两从-1.23版本

------

[TOC]

# 1、kubernetes组件信息

##       1.1 Master节点组件

- **APIServer **：是整个集群的控制中枢，提供集群中各个模块之间的数据交换，并将集群状态和信息存储到分布式键-值(key-value)存储系统Etcd集群中。同时它也是集群管理、资源配额、提供完备的集群安全机制的入口，为集群各类资源对象提供增删改查以及watch的REST API接口。
- **Scheduler - Scheduler**：是集群Pod的调度中心，主要是通过调度算法将Pod分配到最佳的Node节点，它通过APIServer监听所有Pod的状态，一旦发现新的未被调度到任何Node节点的Pod( PodSpec.NodeName为空），就会根据一系列策略选择最佳节点进行调度。
- **Controller Manager** ：是集群状态管理器，以保证Pod或其他资源达到期望值。当集群中某个Pod的副本数或其他资源因故障和错误导致无法正常运行，没有达到设定的值时，Controller Manager会尝试自动修复并使其达到期望状态。
- **Etcd -Etcd**：由Coreos开发，用于可靠地存储集群的配置数据，是一种持久性、轻量型、分布式的键-值（key-value）数据存储组件，作为Kubernetes集群的持久化存储系统。

## 	 1.2 Node节点组件

- **Kubelet**：负责与Master通信协作，管理该节点上的Pod，对容器进行健康检查及监控，同时负责玊报节点和节点上面Pod的状态。
- **Kube-Proxy**：负责各Pod之间的通信和负载均衡，将指定的流量分发到后端正确的机器上。Runtime:负责容器的管理。
- **CoreDNS**：用于Kubernetes集群内部Service的解析，可以让Pod把Service名称解析成Service的IP，然后通过service的IP地址进行连接到对应的应用上。
- **Calico**：符合CNI标准的一个网络插件，它负责给每个Pod分配一个不会重复的IlP，并且把每个节点当做一各“路由器”，这样一个节点的Pod就可以通过IP地址访问到其他节点的Pod。



# 2、安装初始化

⚠️：**生产环境当中一般选择3台master。**

​         **Master节点和Worker节点的IP地址网段区分开；防止后期由于业务增长，节点资源需要扩充，方便运维管理。**

| role                 | ipaddress       | configure                        |
| -------------------- | --------------- | -------------------------------- |
| k8s-master01（etcd ) | 192.168.174.110 | 4 core, 4Gb; 50GBS, CentOS 7.9   |
| k8s-node01           | 192.168.174.120 | 4 core, 16Gb; 100GBS, CentOS 7.9 |
| k8s-node02           | 192.168.174.121 | 4 core, 16Gb; 100GBS, CentOS 7.9 |

##  2.1 所有节点中都需要执行(初始化环境)

```bash
#>>> 关闭防火墙及安全策略
$ systemctl disable --now firewalld NetworkManager
$ sed -ri "s/^SELINUX=enforcing/SELINUX=disabled/" /etc/selinux/config
$ setenforce 0

#>>> 禁用swap分区
$ swapoff -a && sysctl -w vm.swappiness=0 && sed -ri '/^[^#]*swap/s@^@#@' /etc/fstab

#>>> 修改本地解析
$ cat <<-EOF >>/etc/hosts
192.168.174.110     k8s-master01
192.168.174.120     k8s-node01
192.168.174.121     k8s-node02
EOF

#>>> 修改YUM源并且安装epel源（中国科技大学或者阿里源）
$ curl -o /etc/yum.repos.d/docker-ce.repo https://mirrors.ustc.edu.cn/docker-ce/linux/centos/docker-ce.repo
$ sed -i 's#download.docker.com#mirrors.ustc.edu.cn/docker-ce#' /etc/yum.repos.d/docker-ce.repo

$ curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo

$ yum clean all && yum -y install epel-release

$ wget -O /etc/yum.repos.d/epel.repo https://mirrors.aliyun.com/repo/epel-7.repo

#>>> 安装kubernetes的YUM源（阿里云）(v1.23+)
$ cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
EOF
$ yum makecache fast

#>>> 或者v1.24以下的需安装一下源
cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
EOF


#>>> 更新系统内rpm软件包(除内核外)
$ yum -y update --exclude=kernel*

#>>> 查看docker版本
$ yum list docker-ce.x86_64 --showduplicates | sort -r


#>>> 安装所需要的服务及依赖(安装Docker是需到github.com/kubernetes中查看当版本适应什么版本的Docker)
$ yum -y install wget jq psmisc vim net-tools telnet yum-utils \
               device-mapper-persistent-data lvm2 git ntpdate \
               ipvsadm ipset sysstat conntrack libseccomp \
               docker-ce-20.10.* docker-ce-cli-20.10.* containerd 

#>>> 校准时间修改上海时区并且加到开机自启
$ echo "*/5 * * * *        ntpdate -b ntp.aliyun.com" >>/var/spool/cron/root
$ ln -sf /usr/share/zoneinfo/Asia/Shanghai  /etc/localtime
$ echo 'ASia/Shanghai' > /etc/tiomezone

#>>> 服务器之间进行免密验证方便后期进行文件传输,选做
$ ssh-keygen -t rsa
$ for i in k8s-node01 k8s-node02;do ssh-copy-id -i .ssh/id_rsa.pub $i;done

#>>> 设置最大文件打开数
$ cat <<-EOF >>/etc/security/limits.conf
* soft nofile 655360
* hard nofile 131072
* soft nproc 655350
* hard nproc 655350
* soft memlock unlimited
* hard memlock unlimited
EOF

#>>> 生成ipvs内核配置
$ cat <<-EOF >>/etc/modules-load.d/ipvs.conf
ip_vs
ip_vs_lc
ip_vs_wlc
ip_vs_rr
ip_vs_wrr
ip_vs_lblc
ip_vs_lblcr
ip_vs_dh
ip_vs_sh
ip_vs_fo
ip_vs_nq
ip_vs_sed
ip_vs_ftp
ip_vs_sh
nf_conntrack
ip_tables
ip_set
xt_set
ipt_set
ipt_rpfilter
ipt_REJECT
ipip
EOF

#>>> k8s内核配置项
$ cat <<EOF > /etc/sysctl.d/k8s.conf
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
fs.may_detach_mounts = 1
net.ipv4.conf.all.route_localnet = 1
vm.overcommit_memory=1
vm.panic_on_oom=0
fs.inotify.max_user_watches=89100
fs.file-max=52706963
fs.nr_open=52706963
net.netfilter.nf_conntrack_max=2310720
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl =15
net.ipv4.tcp_max_tw_buckets = 36000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_orphans = 327680
net.ipv4.tcp_orphan_retries = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.ip_conntrack_max = 65536
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_timestamps = 0
net.core.somaxconn = 16384
EOF

$ systemctl enable --now docker.service

#>>> 设置Docker镜像加速器并且修改systemd作为cgroug的驱动
$ cat <<-EOF >/etc/docker/daemon.json
{
  "exec-opts": ["native.cgroupdriver=systemd"]
}
EOF

#>>> 重新加载Docker的配置文件且重启
$ systemctl daemon-reload && systemctl restart docker

#>>> 升级所有节点的内核（v4.19+）,Kubernetes官网推荐内核版本
$ wget https://dl.lamp.sh/kernel/el7/kernel-ml-5.10.81-1.el7.x86_64.rpm
$ wget https://dl.lamp.sh/kernel/el7/kernel-ml-devel-5.10.81-1.el7.x86_64.rpm
$ yum localinstall -y kernel-ml-5.10.81-1.el7.x86_64.rpm kernel-ml-devel-5.10.81-1.el7.x86_64.rpm
$ grub2-set-default 0 && grub2-mkconfig -o /etc/grub2.cfg
$ grubby --args="user_namespace.enable=1" --update-kernel="$(grubby --default-kernel)"
$ reboot
```

## 2.2 安装kubernetes组件（v1.23 Master and Node）

```bash
#>>> 查看组件的版本信息
$ yum list kubeadm.x86_64 --showduplicates | sort -r

#>>> Master节点执行
$ yum install -y  kubeadm-1.23*  kubelet-1.23* kubectl-1.23*

#>>> Node节点执行
$ yum install -y  kubeadm-1.23*  kubelet-1.23*

#>>> 查看kubeadm版本
$ kubeadm version

#>>> 将所有jkubelet配置成systemd作为cgroug驱动，保持系统稳定。（Docker亦是如此）
$ cat <<-EOF >/etc/sysconfig/kubelet
KUBELET_EXTRA_ARGS="--cgroup-driver=systemd"
EOF
$ systemctl enable --now kubelet
```

> ⚠️#为什么将kubelet配置成systemd作为cgroug驱动？
> Kubernetes默认设置cgroup驱动（cgroupdriver） 为“systemd”，而Docker服务的cgroup驱动默认值为“cgroupfs”，建议将 其修改为“systemd”，与Kubernetes保持一致。



## 2.3 集群初始化

###    2.3.1 初始化yaml文件(Master01)

kubeadm的初始化控制平面（init）命令和加入节点（join）命令均可以通过指定的配置文件修改默认参数的值。kubeadm将配置文件以 ConfigMap形式保存到集群中，便于后续的查询和升级工作。

kubeadm config子命令提供了对这组功能的支持。 

-  kubeadm config print init-defaults：输出kubeadm init命令默认参数的内容。 
- kubeadm config print join-defaults：输出kubeadm join命令默认参数的内容。 
- kubeadm config migrate：在新旧版本之间进行配置转换。 
- kubeadm config images list：列出所需的镜像列表。 
-  kubeadm config images pull：拉取镜像到本地。

```bash
[root@k8s-master01 ~]# vim /root/kubeadm-config.yaml
---
apiVersion: kubeadm.k8s.io/v1beta2
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: abcdef.0123456789abcdef
  ttl: 24h0m0s
  usages:
  - signing
  - authentication
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: 192.168.174.110
  bindPort: 6443
nodeRegistration:
  criSocket: /var/run/dockershim.sock
  name: k8s-master01
  taints:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master
---
apiServer:
  certSANs:
  - 192.168.174.110
  timeoutForControlPlane: 4m0s
apiVersion: kubeadm.k8s.io/v1beta2
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
controlPlaneEndpoint: 192.168.174.110:6443
controllerManager: {}
dns:
  type: CoreDNS
etcd:
  local:
    dataDir: /var/lib/etcd
imageRepository: registry.cn-hangzhou.aliyuncs.com/google_containers
kind: ClusterConfiguration
kubernetesVersion: v1.23.17
networking:
  dnsDomain: cluster.local
  podSubnet: 172.168.0.0/16
  serviceSubnet: 10.96.0.0/16
scheduler: {}

⚠️:配置文件参数需要修改，修改前备份，或者直接用命令行直接生成新的配置文件，但是仍需要修改配置文件中的参数
[root@k8s-master01 ~]# kubeadm config print init-defaults >/root/kubeadm-config.yaml
  ⚠️配置文件需改参数 
      advertiseAddress: 192.168.174.140   # Master01 的ip地址
      name: k8s-master01                # Master01 的主机名
      - 192.168.174.110                   # master01 ip地址
      controlPlaneEndpoint: 192.168.174.110:6443   # master01 ip地址:端口
      imageRepository: registry.cn-hangzhou.aliyuncs.com/google_containers #镜像仓库地址(阿里)
      kubernetesVersion: v1.23.17        # kubernetes的版本号
      podSubnet: 172.168.0.0/16           # Pod 的网段地址
      serviceSubnet: 10.96.0.0/12        # service 的网段地址 
 
 
#>>> 生成新的初始化文件(可以不生成，区别不大)
[root@k8s-master01 ~]# kubeadm config migrate --old-config kubeadm-config.yaml --new-config new.yaml
```

##    2.4 拉取kubernetes组件镜像

```bash
#>>> 拉取初始化所需要的镜像文件（根据当前配置文件拉去所需要的配置文件）(Master01)
[root@k8s-master01 ~]# kubeadm config images pull --config new.yaml
[config/images] Pulled registry.cn-hangzhou.aliyuncs.com/google_containers/kube-apiserver:v1.23.17
[config/images] Pulled registry.cn-hangzhou.aliyuncs.com/google_containers/kube-controller-manager:v1.23.17
[config/images] Pulled registry.cn-hangzhou.aliyuncs.com/google_containers/kube-scheduler:v1.23.17
[config/images] Pulled registry.cn-hangzhou.aliyuncs.com/google_containers/kube-proxy:v1.23.17
[config/images] Pulled registry.cn-hangzhou.aliyuncs.com/google_containers/pause:3.6
[config/images] Pulled registry.cn-hangzhou.aliyuncs.com/google_containers/etcd:3.5.6-0
[config/images] Pulled registry.cn-hangzhou.aliyuncs.com/google_containers/coredns:v1.8.6

#>>> 初始化集群（生成安全证书并且生成node节点加入集群中的哈希码）(Master01)
[root@k8s-master01 ~]# kubeadm init --config new.yaml --upload-certs

Your Kubernetes control-plane has initialized successfully!
To start using your cluster, you need to run the following as a regular user:
  mkdir -p $HOME/.kube
  sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config
You should now deploy a pod network to the cluster.
Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
  https://kubernetes.io/docs/concepts/cluster-administration/addons/
You can now join any number of the control-plane node running the following command on each as root:
  
  kubeadm join 192.168.174.140:6443 --token abcdef.0123456789abcdef \
    --discovery-token-ca-cert-hash sha256:65e8558fcc0d9964de4ce8de880182df2de6e03d6b3402724e35ab7ff8482033 \
    --control-plane --certificate-key d4be6bdc8043c565516325e270525e24e7ed6ed6c200f836be2bd52f2ad1ab11

Please note that the certificate-key gives access to cluster sensitive data, keep it secret!
As a safeguard, uploaded-certs will be deleted in two hours; If necessary, you can use
"kubeadm init phase upload-certs --upload-certs" to reload certs afterward.

Then you can join any number of worker nodes by running the following on each as root:

kubeadm join 192.168.174.140:6443 --token abcdef.0123456789abcdef \
    --discovery-token-ca-cert-hash sha256:65e8558fcc0d9964de4ce8de880182df2de6e03d6b3402724e35ab7ff8482033

#>>> 如果初始化失败，重置后再次初始化，命令如下（没有失败不要执行）
[root@k8s-master01 ~]# kubeadm reset -f ; ipvsadm --clear  ; rm -rf ~/.kube

  
#>>> 所有Node节点执行
[root@k8s-node01 ~]# kubeadm join 192.168.174.140:6443 --token abcdef.0123456789abcdef --discovery-token-ca-cert-hash sha256:65e8558fcc0d9964de4ce8de880182df2de6e03d6b3402724e35ab7ff8482033

#>>> k8s-master01执行
[root@k8s-master01 ~]# mkdir -p $HOME/.kube
[root@k8s-master01 ~]# sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
[root@k8s-master01 ~]# sudo chown $(id -u):$(id -g) $HOME/.kube/config

#>>> Master01执行查看node状态
[root@k8s-master01 ~]# kubectl get nodes
```

> kubeadm init命令在执行具体的安装操作之前，会执行一系列被称 为pre-flight checks的系统预检查，以确保主机环境符合安装要求，如果检查失败就直接终止，不再进行init操作。

##    2.5 Calico网络插件安装(Master01)

​          Calico网站：https://projectcalico.docs.tigera.io

​              ⚠️ ：注意kubernetes和calico之间的版本关联；详细信息去官网查看

```bash
[root@k8s-master01 ~]# cd /root/ && git clone  https://gitee.com/BRWYZ/kubernetes_install.git
[root@k8s-master01 ~]# cd /root/kubernetes_install && git checkout v1.23+  && cd calico/

#>>> 修改calico配置文件中Pod的网段
[root@k8s-master01 ~]# POD_SUBNET=`cat /etc/kubernetes/manifests/kube-controller-manager.yaml | grep cluster-cidr= | awk -F= '{print $NF}'`
[root@k8s-master01 ~]# sed -i "s#POD_CIDR#${POD_SUBNET}#g" calico.yaml

#>>> 创建calico容器
[root@k8s-master01 ~]# kubectl apply -f calico.yaml

#>>> 查看Pod的信息
[root@k8s-master01 ~]# kubectl get po -n kube-system
 NAME                                       READY   STATUS    RESTARTS        AGE
calico-kube-controllers-6f6595874c-kqvbc   1/1     Running   0               2m15s
calico-node-f2kgm                          1/1     Running   0               2m15s
calico-node-gh9vh                          1/1     Running   0               2m15s
calico-typha-6b6cf8cbdf-g8cl7              1/1     Running   0               2m15s
coredns-65c54cc984-7jp42                   1/1     Running   0               11h
coredns-65c54cc984-cgcbb                   1/1     Running   0               11h
etcd-k8s-master01                          1/1     Running   1 (5m20s ago)   11h
kube-apiserver-k8s-master01                1/1     Running   1 (5m20s ago)   11h
kube-controller-manager-k8s-master01       1/1     Running   1 (5m20s ago)   11h
kube-proxy-rpp8q                           1/1     Running   1 (5m17s ago)   11h
kube-proxy-z5p22                           1/1     Running   1 (5m20s ago)   11h
kube-scheduler-k8s-master01                1/1     Running   1 (5m20s ago)   11h
```



```bash
#>>>  官网下载calico的yaml文件
[root@k8s-master01 ~]#curl https://docs.projectcalico.org/archive/v3.18/manifests/calico-typha.yaml -o calico.yaml
[root@k8s-master01 ~]# vim /root/calico.yaml
  #修改处
    - name: CALICO_IPV4POOL_CIDR
               value: "172.168.0.0/16"  #Pod的网段
             Disable file logging so `kubectl logs` works.

#>>> 生成calico的yaml文件（部署calico网络插件）
[root@k8s-master01 ~]# kubectl apply -f calico.yaml

#>>>  查看是否拉取成功
[root@k8s-master01 ~]# kubectl get po -n kube-system 
```



## 2.6 生成新的token key值

​             ⚠️：由于生成的token值有效期较短，或者有新的master或者node节点需要添加集群当中，所以需要获取新的token值

```bash
#>>> 生成新的master的token值(一般不需要，三台master足够支撑)
$ kubeadm init phase upload-cers --upload-certs

#>>> 生成新的node的token值
$ kubeadm token create --print-join-command

 
#>>> 查看token值过期时间（在/root/new.yaml文件中token: abcdef.0123456789abcdef对应bootstrap-token-abcdef）
$ kubectl get secret -n kube-system
 bootstrap-token-abcdef
$ kubectl get secret bootstrap-token-abcdef -n kube-system -oyaml
  找到 expiration: MjAyMi0xMS0yM1QxNDowNjowOFo=
$ echo "MjAyMi0xMS0yM1QxNDowNjowOFo=" | base64 --decode
```

##    2.7 Metrics  server部署(Master01)

​            在新版的Kubernetes中系统资源的采集均使用Metrics-server，可以通过Metrics采集节点和Pod的内存、磁盘、CPU和网络的使用率。

```bash
#>>> 将Master01节点的front-proxy-ca.crt复制到所有Node节点
[root@k8s-master01 ~]# scp /etc/kubernetes/pki/front-proxy-ca.crt k8s-node0{1..2}:/etc/kubernetes/pki/front-proxy-ca.crt

#>>> 安装Metrics server
[root@k8s-master01 ~]# cd kubernetes_install/kubeadm-metrics-server/
[root@k8s-master01 kubeadm-metrics-server]# kubectl  create -f comp.yaml


#>>> 查看Metrics server状态
[root@k8s-master01 ~]# kubectl get po -n kube-system -l k8s-app=metrics-server
NAME                              READY   STATUS    RESTARTS   AGE
metrics-server-5cf8885b66-8j4nn   1/1     Running   0          46s

#>>> 查看节点状态
[root@k8s-master01 ~]# kubectl top node
  NAME           CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%   
k8s-master01   295m         7%     1338Mi          34%       
k8s-node01     140m         3%     782Mi           20%    

#>>> 查看pod的状态
[root@k8s-master01 ~]# kubectl top po -A
  NAMESPACE     NAME                                       CPU(cores)   MEMORY(bytes)   
kube-system   calico-kube-controllers-6f6595874c-kqvbc   3m           21Mi            
kube-system   calico-node-f2kgm                          56m          109Mi           
kube-system   calico-node-gh9vh                          64m          145Mi           
kube-system   calico-typha-6b6cf8cbdf-g8cl7              4m           29Mi            
kube-system   coredns-65c54cc984-7jp42                   3m           13Mi            
kube-system   coredns-65c54cc984-cgcbb                   3m           16Mi            
kube-system   etcd-k8s-master01                          24m          58Mi            
kube-system   kube-apiserver-k8s-master01                104m         325Mi           
kube-system   kube-controller-manager-k8s-master01       28m          57Mi            
kube-system   kube-proxy-rpp8q                           1m           18Mi            
kube-system   kube-proxy-z5p22                           1m           15Mi            
kube-system   kube-scheduler-k8s-master01                6m           24Mi            
kube-system   metrics-server-5cf8885b66-8j4nn            5m           19Mi 
```

## 2.8 修改Kube-proxy改为ipvs模式(k8s-master01)

初始化集群的时注释了ipvs配置（Master01）,将 `kube-proxy` 模式从 `iptables` 修改为 `ipvs` 是为了提升性能和功能。

**详解：**

1. **性能优势**：`ipvs`可以更有效地处理大量并发连接。这使得它在高流量场景下表现更佳。更好地扩展以处理更多的服务和后端 pod，而 `iptables` 在规则数量非常多时，性能可能会显著下降。

2. **低延迟和高吞吐量**：`ipvs` 通过在内核空间处理数据包，减少了用户空间和内核空间之间的切换，从而提高了数据包处理的效率，带来更低的延迟和更高的吞吐量。

3. **快速规则应用**：`ipvs` 在处理和应用网络规则时速度更快，特别是在规则变更频繁的情况下。
4. **多种调度算法**：`ipvs` 提供了多种负载均衡算法（如轮询、最小连接、最短延迟等），可以根据具体需求选择最合适的算法，而 `iptables` 则缺乏这种灵活性。
5. **稳定性**：`ipvs` 的实现更加稳定，尤其是在大型集群中，它能更好地应对复杂的网络环境和高负载。
6. **原生健康检查**：`ipvs` 支持后端服务器的健康检查，可以自动剔除不健康的节点，从而提高服务的可用性和稳定性。
7. **简化的规则管理**：`ipvs` 使用专用的内核模块管理规则，相比 `iptables` 更加简洁和高效。`iptables` 规则在处理和管理上会更加复杂，特别是当规则数量增多时。
8. **维护方便**：`ipvs` 的规则结构更清晰，维护起来更为方便，不像 `iptables` 那样需要处理大量的规则链和复杂的规则匹配逻辑。

```bash
[root@k8s-master01 ~]# kubectl edit cm kube-proxy -n kube-system
  	# 找到mode字段添加ipvs

#>>> 更新Kube-Proxy的Pod
[root@k8s-master01 ~]# kubectl patch daemonset kube-proxy -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"date\":\"`date +'%s'`\"}}}}}" -n kube-system
  daemonset.apps/kube-proxy patched

#>>> 验证Kube-Proxy模式
[root@k8s-master01 ~]# curl 127.0.0.1:10249/proxyMode
ipvs
```

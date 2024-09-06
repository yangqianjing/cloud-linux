# k8s学习文档

## 部署k8s环境

### 环境准备

| 主机名字   | ip           | 节点 |
| ---------- | ------------ | ---- |
| k8s-master | 172.17.10.20 |      |
| k8s-node01 | 172.17.10.31 |      |
| k8s-node02 | 172.17.10.32 |      |

### 升级内核

```bash
[root@localhost ~]# cat /etc/yum.repos.d/elrepo.repo 
[elrepo]
name=elrepo
baseurl=https://mirrors.aliyun.com/elrepo/archive/kernel/el7/x86_64
gpgcheck=0
enabled=1
[root@localhost ~]# yum clean all && yum makecache fast
[root@localhost ~]# yum --enablerepo=elrepo install kernel-lt-devel kernel-lt -y
[root@localhost ~]# grub2-set-default 0
[root@localhost ~]# vim /etc/default/grub
GRUB_DEFAULT=saved 改为 GRUB_0=saved 
[root@localhost ~]# grub2-mkconfig -o /boot/grub2/grub.cfg
[root@localhost ~]# reboot
[root@localhost ~]# uname -r
5.4.278-1.el7.elrepo.x86_64
```

### 开始安装部署

```bash
[root@k8s-master ~]# systemctl stop firewalld && setenforce 0
[root@k8s-master ~]# swapoff -a && sysctl -w vm.swappiness=0 && sed -ri '/^[^#]*swap/s@^@#@' /etc/fstab
vm.swappiness = 0
root@k8s-master ~]# sed -ri "s/^SELINUX=enforcing/SELINUX=disabled/" /etc/selinux/config
[root@k8s-node01 ~]# cat <<-EOF >>/etc/hosts
172.17.10.20 k8s-master
172.17.10.31 k8s-node01
172.17.10.32 k8s-node02
EOF
[root@k8s-master ~]# cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
EOF
[root@k8s-node02 ~]# yum makecache fast
[root@k8s-master ~]# curl -o /etc/yum.repos.d/docker-ce.repo https://mirrors.ustc.edu.cn/docker-ce/linux/centos/docker-ce.repo
[root@k8s-master ~]# sed -i 's#download.docker.com#mirrors.ustc.edu.cn/docker-ce#' /etc/yum.repos.d/docker-ce.repo
[root@k8s-master ~]# yum -y install wget jq psmisc vim net-tools telnet yum--utils device-mapper-persistent-data lvm2 git ntpdate ipvsadm ipset sysstat conntrack libseccomp docker-c*e-20.10.* docker-ce-cli-20.10.* containerd.io
[root@k8s-master ~]# echo "*/5 * * * *        ntpdate -b ntp.aliyun.com" >>/var/spool/cron/root
[root@k8s-master ~]# ln -sf /usr/share/zoneinfo/Asia/Shanghai  /etc/localtime
[root@k8s-master ~]# echo 'ASia/Shanghai' > /etc/tiomezone
[root@k8s-master ~]# cat <<-EOF >>/etc/security/limits.conf
* soft nofile 655360
* hard nofile 131072
* soft nproc 655350
* hard nproc 655350
* soft memlock unlimited
* hard memlock unlimited
EOF
[root@k8s-master ~]#  cat <<-EOF >>/etc/modules-load.d/ipvs.conf
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
[root@k8s-master ~]#  cat <<EOF > /etc/sysctl.d/k8s.conf
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
[root@k8s-master ~]# systemctl enable --now docker.service
[root@k8s-master ~]#  cat <<-EOF >/etc/docker/daemon.json
{
   "exec-opts": ["native.cgroupdriver=systemd"]
}
EOF
[root@k8s-master ~]# systemctl daemon-reload && systemctl restart docker

```

### 安装kubernetes组件

```bash
# master节点执行
[root@k8s-master ~]# yum install -y  kubeadm-1.23*  kubelet-1.23* kubectl-1.23*
# node节点执行
[root@k8s-node01 ~]# yum install -y  kubeadm-1.23*  kubelet-1.23*
# 所有节点执行
[root@k8s-node01 ~]# cat <<-EOF >/etc/sysconfig/kubelet
KUBELET_EXTRA_ARGS="--cgroup-driver=systemd"
EOF
[root@k8s-master ~]# systemctl enable --now kubelet
```

### 集群初始化

```bash
[root@k8s-master ~]# cat /root/kubeadm-config.yaml
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
  advertiseAddress: 172.17.10.20
  bindPort: 6443
nodeRegistration:
  criSocket: /var/run/dockershim.sock
  name: k8s-master
  taints:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master
---
apiServer:
  certSANs:
  - 172.17.10.20
  timeoutForControlPlane: 4m0s
apiVersion: kubeadm.k8s.io/v1beta2
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
controlPlaneEndpoint: 172.17.10.20:6443
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
[root@k8s-master ~]# kubeadm config migrate --old-config kubeadm-config.yaml --new-config new.yaml
```

### 拉取组件镜像

```bash
[root@k8s-master ~]# kubeadm config images pull --config new.yaml
#>>> 初始化集群（生成安全证书并且生成node节点加入集群中的哈希码）(Master)
[root@k8s-master ~]# kubeadm init --config new.yaml --upload-certs
# 所有node节点执行
[root@k8s-node01 ~]# kubeadm join 172.17.10.20:6443 --token abcdef.0123456789abcdef \
> --discovery-token-ca-cert-hash sha256:608450aba8354003937e802a1da5afc9b017400e21ba43a20eddefc8e93b7d8f
# master节点执行
[root@k8s-master ~]# mkdir -p $HOME/.kube
[root@k8s-master ~]#   sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
[root@k8s-master ~]#   sudo chown $(id -u):$(id -g) $HOME/.kube/config

```

### calico网络插件下载(master)

```bash
[root@k8s-master ~]# git clone  https://gitee.com/BRWYZ/kubernetes_install.git
正克隆到 'kubernetes_install'...
remote: Enumerating objects: 83, done.
remote: Counting objects: 100% (83/83), done.
remote: Compressing objects: 100% (74/74), done.
remote: Total 83 (delta 35), reused 11 (delta 4), pack-reused 0
Unpacking objects: 100% (83/83), done.
[root@k8s-master ~]# cd /root/kubernetes_install && git checkout v1.23+  && cd calico/
分支 v1.23+ 设置为跟踪来自 origin 的远程分支 v1.23+。
切换到一个新分支 'v1.23+'
[root@k8s-master calico]# POD_SUBNET=`cat /etc/kubernetes/manifests/kube-controller-manager.yaml | grep cluster-cidr= | awk -F= '{print $NF}'`
[root@k8s-master calico]# sed -i "s#POD_CIDR#${POD_SUBNET}#g" calico.yaml
[root@k8s-master calico]# kubectl apply -f calico.yaml
[root@k8s-master calico]# scp /etc/kubernetes/pki/front-proxy-ca.crt k8s-node0{1..2}:/etc/kubernetes/pki/front-proxy-ca.crt
[root@k8s-master ~]# cd kubernetes_install/kubeadm-metrics-server/
[root@k8s-master kubeadm-metrics-server]#  kubectl  create -f comp.yaml
[root@k8s-master kubeadm-metrics-server]# kubectl top node
NAME         CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%   
k8s-master   167m         4%     1707Mi          44%       
[root@k8s-master ~]# docker tag registry.cn-hangzhou.aliyuncs.com/yangqianjing/rancher:v2.7.0  rancher/rancher:v2.7.0
k8s-node01   87m          2%     1049Mi          27%       
k8s-node02   468m         11%    1134Mi          29%     
```

## 使用界面话工具rancher

```bash
[root@k8s-master ~]# docker pull registry.cn-hangzhou.aliyuncs.com/yangqianjing/rancher:v2.7.0
[root@k8s-master ~]# docker tag registry.cn-hangzhou.aliyuncs.com/yangqianjing/rancher:v2.7.0  rancher/rancher:v2.7.0
[root@k8s-master ~]# docker run -d  --name rancher --restart=unless-stopped --privileged   -p 80:80 -p 443:443   -v /var/lib/rancher:/var/lib/rancher/   -v /var/log/rancher/auditlog:/var/log/auditlog    rancher/rancher:v2.7.0
75d64378f0d3d039c324405d47daba787459db5d8296c939c1cb0f49bb1f819b
[root@k8s-master ~]# docker ps -a|grep rancher
75d64378f0d3   rancher/rancher:v2.7.0                                          "entrypoint.sh"          About a minute ago   Up About a minute         0.0.0.0:80->80/tcp, :::80->80/tcp, 0.0.0.0:443->443/tcp, :::443->443/tcp   rancher
[root@k8s-master ~]# docker logs 75d64378f0d3 2>&1 | grep "Bootstrap Password:"
2024/08/31 14:33:29 [INFO] Bootstrap Password: fhffn2gd6pllrprrkp2gcs9bw2jrd29kxq4vn67mpdw7wcmdnnmqlv
# 浏览器访问 https://ip
```

```bash

[root@k8s-master ~]# docker pull registry.cn-hangzhou.aliyuncs.com/yangqianjing/rancher-agent:v2.7.0
```




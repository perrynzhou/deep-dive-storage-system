# 0. 编译环境
```shell
# CentOS
$ uname -r
3.10.0-1160.59.1.el7.x86_64
```

# 1. 依赖包安装

```shell
$ yum install -y epel-release gcc make autoconf automake libtool rpm-build libtool rpm-build libtirpc-devel libblkid-devel libuuid-devel libudev-devel openssl-devel zlib-devel libaio-devel libattr-devel elfutils-libelf-devel kernel-devel-$(unmame -r) python python2-devel python-setuptools python-cffi libffi-devel ncompress
$ yum install --enablerepo=epel dkms python-packaging
$ yum install -y python36-packaging python36-devel
```

# 2. 编译安装
```shell
$ sh autogen.sh
$ ./configure
$ make -j8 rpms
```


# 3. 安装rpm包
```shell
$ yum localinstall *.$(uname -p).rpm *.noarch.rpm
```

# 4. 创建一个zfs挂载点
```shell
# 创建zpool
$ zpool create -f -o ashift=12 -O atime=off zhongylpool /dev/sdf
$ zpool list
NAME          SIZE  ALLOC   FREE  CKPOINT  EXPANDSZ   FRAG    CAP  DEDUP    HEALTH  ALTROOT
zhongylpool  19.5G   492K  19.5G        -         -     0%     0%  1.00x    ONLINE  -
# 创建zfs mountpoint
$ zfs create -o mountpoint=/zhongylzfs zhongylpool/zhongylzfs
$ zfs list
NAME                     USED  AVAIL  REFER  MOUNTPOINT
zhongylpool              576K  18.9G    96K  /zhongylpool
zhongylpool/zhongylzfs    96K  18.9G    96K  /zhongylzfs
```

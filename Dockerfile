
# 使用 CentOS 7.9 作为基础镜像
FROM centos:7.9.2009

RUN curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo && \
    yum clean all && \
    yum makecache

# 安装开发工具和依赖包
RUN yum install -y net-tools
RUN yum install -y gdb
RUN yum install -y iproute
RUN yum install -y psmisc

RUN mkdir -p /root/seth/cbuild_Debug
RUN mkdir -p /root/seth/cbuild_Release
RUN mkdir -p /root/seth/zjnodes_local
# 设置工作目录
COPY ./cbuild_Release/seth /root/seth/cbuild_Release/seth
COPY ./cbuild_Debug/seth /root/seth/cbuild_Debug/seth
COPY ./zjnodes_local /root/seth/zjnodes_local
COPY ./docker_simple_dep.sh /root/seth/
COPY ./init_accounts3 /root/seth/
COPY ./shards3 /root/seth/
COPY ./root_nodes /root/seth/
COPY ./python3.10 /root/seth/
COPY ./python /root/seth/
WORKDIR /root/seth

# 创建一个默认的命令来查看系统状态
# CMD ["sh", "docker_simple_dep.sh 4 Debug"]

# MyIpsec

## 介绍

本项目为2014级《系统软件课程设计》大作业。

基于Netfilter的队列功能实现的网络层数据报加密系统。

## 构建

### 依赖

+ libnetfilter_queue
+ qt5.7
+ libev
+ glog
+ mbedtls
+ cmake

### 编译步骤

安装依赖

```bash
sudo apt install build-essentials git libev-dev libnetfilter-queue-dev cmake qt5-default pkg-config libmbedtls-dev libgoogle-glog-dev
```

克隆代码并编译

```bash
git clone https://github.com/lcdtyph/myipsec
cd myipsec

cmake .
make
```

可执行文件生成在```./build```文件夹下```MyIpsec```
执行```MyIpsec```

```bash
sudo ./build/MyIpsec
```

## License

>lcdtyph <lcdtyph@gmail.com>
Copyright (C) 2017  lcdtyph
>
>This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
>
>This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
>
>You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

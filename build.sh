#!/bin/bash

# 将当前目录下的 .git 文件夹重命名为 .git_bak
mv .git .git_bak

# 在当前目录下执行 make 命令
make CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64 -j$(nproc)

# 将 .git_bak 文件夹重命名回 .git
mv .git_bak .git

rm -f /home/p0lar1s/islet_test/out/Image
rm -f /home/p0lar1s/islet_test/buildroot-2023.02.5/output/images/Image

cp /home/p0lar1s/islet_test/linux-cca-cca-full-rfc-v1/arch/arm64/boot/Image /home/p0lar1s/islet_test/out/
cp /home/p0lar1s/islet_test/linux-cca-cca-full-rfc-v1/arch/arm64/boot/Image /home/p0lar1s/islet_test/buildroot-2023.02.5/output/images/

# apk2bpk
步步高学习机加密格式和普通格式互相转换
对比https://github.com/TryExceptElseFinally/eebbk_apk2bpk_converter
最终发现原始 apk2bpk 代码的主要问题：

1. 中央目录异或不对称
      解码时对中央目录缓冲区重复异或，导致文件名/注释等损坏。
2. 本地文件头字段错误
      对非 data descriptor 条目填入了 0xFFFFFFFF，导致 ZIP 解压失败。
3. APK 签名块处理错误
      签名块搜索方式不对（用跳过 0x00 猜测），且写入时漏掉了签名块尾部的 8 字节大小和 16 字节魔数，造成签名丢失。
4. EOCD 注释字段越界
      EOCD 的 extra_length 可能异常，导致写入时访问非法地址，引发段错误。
5. 重建文件结构导致偏移混乱
      原始代码试图以原始偏移写入新文件，但文件顺序可能变化，导致 ZIP 结构无效。

最终采用就地转换思路，直接在内存中修改魔数和必要字段，不移动任何数据，签名块完美保留，BPK 可安装，还原后 APK 签名验证通过。
APK2BPK
将Android apk转换为BBK BPK全加密格式

编码与解码的工作原理
显然用异或
，想了解更多吗？https://azwhikaru.com/11.html

感谢
azwhikaru@github.com

# AK3 本地补丁

基线：`config/config` 钉的 `sukisu=4bec532dd447e2852aa8932afa768255350c103a`
（`SukiSU-Nova/SukiSU-Nova` → `builtin` 分支）。工作流 clone 完立刻按文件名顺序
`git apply`，任何一份失败就 `exit 1`。补丁只改 `KernelSU/`（KernelSU 源码树），
不碰 GKI 内核树和 SUSFS 补丁。

| 补丁 | 解决的问题 |
| --- | --- |
| `0001-sukisu-avc-selinux-link.patch` | 功能 4「隐藏 SELinux 修改」和功能 10003「AVC 日志伪装」没有内核实现 |
| `0002-sukisu-keep-app-seccomp.patch` | manager 首页「Seccomp 状态：未启用」 |

---

## 0001 — 功能 4 与 10003 接线

| 文件 | 作用 |
| --- | --- |
| `kernel/feature/selinux_hide.c` | 接管 `/sys/fs/selinux/access`、`/context` 的写路径 |
| `kernel/feature/avc_spoof.c/.h` | kprobe `slow_avc_audit`，把 su/ksu 的 tsid 换成 priv_app |
| `kernel/hook/patch_memory.c/.h`（新增） | fixmap 别名 + `stop_machine` 改写 `.rodata` |
| `kernel/include/uapi/feature.h` | 新增 `KSU_FEATURE_AVC_SPOOF = 10003` |
| `kernel/policy/feature.c` | 注册名字 `avc_spoof`（`force_feature=avc_spoof:1` 可用） |
| `kernel/ksu_main.c` | unity build 引入新 `.c`、`ksu_avc_spoof_init()` |
| `kernel/runtime/ksud.c` | `on_post_fs_data()` → `ksu_avc_spoof_late_init()` |

### 为什么原来“开关连不上”

**功能 4**：`my_write_access()` / `my_write_context()` 是完整实现（含 `avd.seqno = 1`），
但**没有任何调用点**，`ksu_selinux_hide_enable()` 只检查 `backup_sepolicy` 就 `return 0`。
selinuxfs 的写入口是常量表

```c
static ssize_t (*const write_op[])(struct file *, char *, size_t) = {
    [SEL_ACCESS] = sel_write_access,
    ...
};
```

`selinux_transaction_write()` 只做 `write_op[ino](file, data, size)`，所以只能替换表项。
补丁用 `find_kernel_symbol_exact("write_op")` 取表地址（真机 `/proc/kallsyms` 里确有
`d write_op`），改写 `write_op[SEL_CONTEXT=5]`、`write_op[SEL_ACCESS=6]`；
`.rodata` 只读，`ksu_patch_text()` 走 `init_mm` 页表取物理地址 → `FIX_TEXT_POKE0` 别名写入，
`stop_machine` 保护。`uid < 10000` 直接走原 handler。

**功能 10003**：内核 `feature.h` 只到 16，`ksu_get_feature(10003)` 返回 `-EINVAL`
（dmesg：`KernelSU: feature: invalid feature_id 10003`）。补丁补上 id 并挂 kprobe。

### 验证

```sh
ksud feature list | grep -E 'selinux_hide|avc_spoof'
dmesg | grep -E 'write_op hooked|slow_avc_audit spoofing enabled'
```

### 踩过的坑：`KSU_FEATURE_MAX` 跨过 64

`KSU_FEATURE_MAX` 从 17 抬到 10004 后，`BITS_TO_LONGS()` 从 1 段变成 157 段，
`policy/feature.c` 的 `DECLARE_BITMAP(forced_mask, ...)` 就和
`extension/extension.c` 的同名位图在 unity build（两个 .c 都 #include 进
`ksu_main.o`）里变成“同名不同类型”，编译报：

```
error: redefinition of 'forced_mask' with a different type:
       'unsigned long [157]' vs 'unsigned long [1]'
```

原来两者都是 1 段（`KSU_EXTENSION_MAX` 也很小），所以撞名但类型相同、被静默合并。
补丁里把 `policy/feature.c` 的那两个改名为 `feature_forced_mask` /
`feature_forced_pending`，行为不变。

---

## 0002 — 让应用的 seccomp 状态正常显示

### 现象与根因

manager 首页 `Seccomp 状态` 读的是 `Os.prctl(21 /* PR_GET_SECCOMP */)`（自身进程的
`seccomp.mode`）。真机实测：

```
com.mobile.tools.manager  10351  Seccomp: 0   <- 显示了"未启用"
com.termux                10418  Seccomp: 0
com.omarea.vtools         10448  Seccomp: 0
org.mozilla.firefox_beta  10405  Seccomp: 2
com.android.systemui       1000  Seccomp: 2
```

共同点不是「新启动的进程」，而是**这三个都在 KSU 的 allowlist 里**。
原因在 `kernel/hook/lsm_hook.c`：`handle_zygote_setresuid()` /
`handle_zygote_next_setresuid()` 在 zygote 给子进程 setresuid 的那一刻，对
manager 和所有 root 授权应用直接调用 `disable_seccomp()`
（`policy/app_profile.c`：清 `TIF_SECCOMP`、`mode = 0`、释放 filter）。

上游这么做是因为 root 授权应用要 exec `su`/`ksud`，而 Android 的 app seccomp
策略挡掉 `mount`、`setns` 等特权系统调用——但代价就是应用自己再也看不到 filter。

### 改法

不在 setresuid 时释放，改成**只在真正要变成 su/ksud 的那个子进程里释放**：

- `hook/lsm_hook.c`：4 处 `disable_seccomp()` 全部去掉（manager×2、allow-uid×2），
  `ksu_install_fd()` / umount / susfs 逻辑原样保留；`extern` 声明提到文件顶部。
- `feature/sucompat.c`：`ksu_handle_execveat_sucompat()` 里，在
  `escape_with_root_profile()` 成功之后、把文件名改写成 `ksud` 之前调用
  `disable_seccomp()`——此时 `current` 就是即将 exec 成 su 的子进程。

结果：应用（含 manager）保留 zygote 装好的 filter → `/proc/<pid>/status` 和
`PR_GET_SECCOMP` 都是 2，首页显示「Filter」；`su` 的 root shell 仍然无 filter，
行为与改之前一致。

> 注意：`#else` 分支（`CONFIG_KSU_SUSFS` 未定义时走 LSM `task_fix_setuid`）
> 保留原来的 `disable_seccomp()`，因为那条路径的 `__is_su_allowed()` 会用
> `TIF_SECCOMP` 直接拒绝 su。本 AK3 是 SUSFS 构建，走的是 `#ifdef` 那条。

### 验证

```sh
# 应用进程（含 manager）：应为 2
grep Seccomp /proc/$(pidof com.mobile.tools.manager)/status
# root shell（su 出来的）：应为 0
su -c 'grep Seccomp /proc/self/status'
```

回滚：`git -C KernelSU apply -R "$GITHUB_WORKSPACE/patches/0002-sukisu-keep-app-seccomp.patch"`

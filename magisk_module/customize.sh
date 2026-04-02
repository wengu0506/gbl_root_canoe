#!/system/bin/sh

ui_print "- Verifying device model"
_model=$(getprop ro.product.model 2>/dev/null)
_name=$(getprop ro.product.name 2>/dev/null)
_incr=$(getprop ro.build.version.incremental 2>/dev/null)
ui_print "- Device verified: $_model / $_name / $_incr"
ui_print "- Setting permissions"
set_perm_recursive "$MODPATH/bin" 0 0 0755 0755
set_perm_recursive "$MODPATH/webroot" 0 0 0755 0644
set_perm "$MODPATH/module.prop" 0 0 0644
set_perm "$MODPATH/skip_mount" 0 0 0644
set_perm "$MODPATH/customize.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755

detect_current_slot() {
  case "$(getprop ro.boot.slot_suffix 2>/dev/null)" in
    _a) printf '%s\n' '_a' ;;
    _b) printf '%s\n' '_b' ;;
    *)  return 1 ;;
  esac
}
BY_NAME_DIR="/dev/block/by-name"
RUNTIME_DIR="$MODPATH/tmp"
mkdir -p "$RUNTIME_DIR"
partition_path() { printf '%s\n' "$BY_NAME_DIR/${1}${2}"; }
#install efisp
ui_print "确保你的内核没有Baseband Guard，设备BL锁已经解锁"
ui_print "确保你的设备是8gen5/8elitegen5"
ui_print "检测漏洞中..."
current_slot=$(detect_current_slot 2>/dev/null)
ui_print "请选择是否第一次安装假回锁"
ui_print "音量上为是（全新安装，需要格式化)"
ui_print "音量下为否（如果之前安装过一次假回锁或者刚刚首次安装并格式化，建议选择否）"
ui_print "如果选择是，将会安装包含补丁的efisp 然后重启recovery 进行格式化，格式化后请安装一次这个模块来完成安装，这时选择否"
ui_print "如果选择否，将会安装OTA更新补丁，每次OTA更新后都需要打开这个模块来安装补丁，来保留BL版本，安装完成后重启系统即可"
while true; do #循环等待用户按键选择，音量上为是，音量下为否
  keyevent=$(timeout 0.5 getevent -l 2>/dev/null)
  if echo "$keyevent" | grep -q "KEY_VOLUMEUP"; then
    ui_print "选择了是，正在安装包含补丁的efisp"
    if [ -z "$current_slot" ]; then
      ui_print "无法识别当前槽位，已中止安装"
      abort "cannot detect current slot"
    fi
    abl_part=$(partition_path abl "$current_slot")
    $MODPATH/bin/extractfv -o "$MODPATH/tmp" -v "$abl_part" >> "$MODPATH/tmp/extract.log" 2>&1
    $MODPATH/bin/patch_abl "$MODPATH/tmp/LinuxLoader.efi" "$MODPATH/tmp/patched.efi" >> "$MODPATH/tmp/patch.log" 2>&1
    if [ ! -f "$MODPATH/tmp/patched.efi" ]; then
      ui_print "补丁应用失败，已中止安装"
      abort "patch failed"
    fi
    if grep -q "Warning: Failed to patch ABL GBL" "$RUNTIME_DIR/patch.log"; then
      ui_print "没有GBL漏洞，安装失败，已中止安装"
      abort "no exploit"
    fi
    if ! blockdev --setrw "/dev/block/by-name/efisp" >> "$MODPATH/tmp/flash.log" 2>&1; then
      ui_print "efisp 分区设置可写失败，已中止安装"
      abort "setrw failed"
    fi
    if ! dd if="$MODPATH/tmp/patched.efi" of=/dev/block/by-name/efisp bs=4M conv=fsync >> "$MODPATH/tmp/flash.log" 2>&1; then
      ui_print "efisp 分区刷写失败，已中止安装"
      abort "flash failed"
    fi
    sync
    ui_print "安装完成，请重启到recovery进行格式化，格式化后请安装一次这个模块来完成安装，这时选择否"
    rm -rf "$RUNTIME_DIR"
    break
  elif echo "$keyevent" | grep -q "KEY_VOLUMEDOWN"; then
    ui_print "选择了否，正在安装OTA更新模块"
    ui_print "安装完成，请重启系统即可"
    rm -rf "$RUNTIME_DIR"
    break
  fi
done

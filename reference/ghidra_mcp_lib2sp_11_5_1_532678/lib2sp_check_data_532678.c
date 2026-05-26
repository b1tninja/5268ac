/* Ghidra MCP — lib2sp_check_data @ 0x00020880 (532678) */

int lib2sp_check_data(int *param_1)
{
  if (param_1 == (int *)0x0) {
    return 0x16;
  }
  if (*param_1 == 6) {
    return param_1[2] != 0 ? param_1[2] : 0x16;
  }
  if (param_1[1] != 3) {
    return 0x16;
  }
  if (1 < *param_1 - 3U) {
    return *param_1 != 6 ? 0x10 : param_1[2];
  }
  if (*(char *)(param_1 + 0x141) == '\0') {
    if ((param_1[0x142] | param_1[0x143]) != 0) {
      return param_1[2];
    }
  }
  *(undefined1 *)(param_1 + 0x141) = 1;
  lib2sp_internal_check_data(param_1);
  return param_1[2];
}

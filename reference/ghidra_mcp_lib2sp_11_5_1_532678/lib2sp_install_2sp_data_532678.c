/* Ghidra MCP — lib2sp_install_2sp_data @ 0x0001f60c (532678)
 * Indirect jump on *param_1 (state 0..6); states >= 7 return EINVAL.
 * Jump table @ PTR_LAB_00036774 + state*4 + 0x6330.
 */

undefined4 lib2sp_install_2sp_data(uint *param_1,int param_2,int param_3,undefined4 *param_4)

{
  undefined4 uVar1;
  uint uVar2;
  
  uVar1 = 0x16;
  if (((param_1 != (uint *)0x0) && (param_2 != 0)) && (param_4 != (undefined4 *)0x0)) {
    uVar2 = param_1[0x182];
    while( true ) {
      if (uVar2 != 0) {
        (*(code *)PTR_lib2sp_log_00036798)
                  (param_1,6,PTR_LAB_00036774 + 0x5790,*(undefined4 *)(uVar2 + 8));
        param_1[0x182] = 0;
      }
      if (*param_1 < 7) {
        uVar1 = (*(code *)(&_gp_1 + *(int *)(PTR_LAB_00036774 + *param_1 * 4 + 0x6330)))();
        return uVar1;
      }
      if (param_3 < 1) break;
      uVar2 = param_1[0x182];
    }
    *param_4 = 0;
    uVar1 = 0;
  }
  return uVar1;
}

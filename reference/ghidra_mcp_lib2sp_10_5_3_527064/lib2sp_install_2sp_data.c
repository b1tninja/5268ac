
undefined4 lib2sp_install_2sp_data(uint *param_1,int param_2,int param_3,undefined4 *param_4)

{
  uint uVar1;
  undefined4 uVar2;
  int in_t9;
  undefined1 auStack_78 [48];
  undefined1 *puStack_48;
  
  if (param_1 != (uint *)0x0) {
    if (param_2 == 0) {
      return 0x16;
    }
    puStack_48 = auStack_78;
    if (param_4 != (undefined4 *)0x0) {
      uVar1 = param_1[0x172];
      while( true ) {
        if (uVar1 != 0) {
          (**(code **)(&UNK_00014ca4 + in_t9))
                    (param_1,6,*(int *)(&UNK_00014c84 + in_t9) + 0x39b0,*(undefined4 *)(uVar1 + 8));
          param_1[0x172] = 0;
        }
        if (*param_1 < 7) break;
        if (param_3 < 1) {
          *param_4 = 0;
          return 0;
        }
        uVar1 = param_1[0x172];
      }
                    /* WARNING: Could not recover jumptable at 0x0001f88c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      uVar2 = (*(code *)(&UNK_0001cc60 +
                        *(int *)(*(int *)(&UNK_00014c84 + in_t9) + 0x4138 + *param_1 * 4) + in_t9))
                        ();
      return uVar2;
    }
  }
  return 0x16;
}



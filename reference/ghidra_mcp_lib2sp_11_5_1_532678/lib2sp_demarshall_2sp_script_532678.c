/* Ghidra MCP — demarshall_2sp_script @ 0x000154d8 (532678 lib2sp.so.0.0.0) */

int demarshall_2sp_script
              (int param_1,uint param_2,uint *param_3,int *param_4,int *param_5,int *param_6)

{
  undefined4 uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;

  iVar4 = 0;
  iVar5 = iVar4;
  if (0x33 < (int)param_2) {
    uVar1 = nu_ngeth32(param_1,param_3);
    uVar1 = nu_ngeth32(uVar1,param_3 + 1);
    uVar1 = nu_ngeth32(uVar1,param_3 + 2);
    uVar1 = nu_ngeth32(uVar1,param_3 + 3);
    uVar1 = nu_ngeth32(uVar1,param_3 + 4);
    uVar1 = nu_ngeth32(uVar1,param_3 + 5);
    uVar1 = nu_ngeth32(uVar1,param_3 + 6);
    uVar1 = nu_ngeth32(uVar1,param_3 + 7);
    uVar1 = nu_ngeth32(uVar1,param_3 + 8);
    uVar1 = nu_ngeth32(uVar1,param_3 + 10);
    uVar1 = nu_ngeth64(uVar1,param_3 + 0xc);
    nu_ngeth64(uVar1,param_3 + 0xc);
    if ((0x33 < *param_3) && (*param_3 <= param_2)) {
      iVar5 = 0;
      if (param_3[2] + param_3[3] <= param_2) {
        uVar3 = param_3[4];
        iVar5 = 0;
        if (uVar3 + param_3[5] <= param_2) {
          uVar2 = param_3[7];
          iVar5 = iVar4;
          if (uVar2 + param_3[8] <= param_2) {
            *param_4 = param_1 + param_3[2];
            *param_5 = param_1 + uVar3;
            *param_6 = param_1 + uVar2;
            iVar5 = param_1 + param_2;
          }
        }
      }
    }
  }
  return iVar5;
}

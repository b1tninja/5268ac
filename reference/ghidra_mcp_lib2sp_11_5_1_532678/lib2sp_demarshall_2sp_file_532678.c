/* Ghidra MCP — demarshall_2sp_file @ 0x000149d8 (532678 lib2sp.so.0.0.0) */

int demarshall_2sp_file(int param_1,uint param_2,int param_3,int *param_4,int *param_5)
{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;

  iVar1 = 0;
  if (0x1f < (int)param_2) {
    uVar2 = nu_ngeth32(param_1,param_3);
    uVar2 = nu_ngeth32(uVar2,param_3 + 4);
    uVar2 = nu_ngeth32(uVar2,param_3 + 8);
    uVar2 = nu_ngeth32(uVar2,param_3 + 0xc);
    uVar2 = nu_ngeth32(uVar2,param_3 + 0x10);
    uVar2 = nu_ngeth32(uVar2,param_3 + 0x14);
    uVar2 = nu_ngeth32(uVar2,param_3 + 0x18);
    uVar2 = nu_ngeth32(uVar2,param_3 + 0x1c);
    uVar3 = *(uint *)(param_3 + 4);
    if (*(uint *)(param_3 + 0x10) <= *(uint *)(param_3 + 4)) {
      uVar3 = *(uint *)(param_3 + 0x10);
    }
    uVar2 = nu_ngeth32(uVar2,param_3 + 0x20);
    if ((((uVar3 < 100) || ((int)param_2 < 100)) || (*(uint *)(param_3 + 0x20) < 100)) ||
       (param_2 < *(uint *)(param_3 + 0x20))) {
      *(undefined4 *)(param_3 + 0x20) = 0x20;
      *(undefined4 *)(param_3 + 0x2c) = *(undefined4 *)(param_3 + 0x18);
      *(undefined4 *)(param_3 + 0x34) = *(undefined4 *)(param_3 + 0x1c);
    }
    else {
      uVar2 = nu_ngeth64(uVar2,param_3 + 0x28);
      uVar2 = nu_ngeth64(uVar2,param_3 + 0x30);
      *(undefined4 *)(param_3 + 0x18) = *(undefined4 *)(param_3 + 0x2c);
      *(undefined4 *)(param_3 + 0x1c) = *(undefined4 *)(param_3 + 0x34);
    }
    if ((uint)(*(int *)(param_3 + 4) + *(int *)(param_3 + 8)) <= param_2) {
      *param_4 = param_1 + *(int *)(param_3 + 4);
      if ((uint)(*(int *)(param_3 + 0x10) + *(int *)(param_3 + 0x14)) <= param_2) {
        *param_5 = param_1 + *(int *)(param_3 + 0x10);
        iVar1 = param_1 + param_2;
      }
    }
  }
  return iVar1;
}

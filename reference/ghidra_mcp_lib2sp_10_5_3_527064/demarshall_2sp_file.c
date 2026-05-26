
undefined1 *
demarshall_2sp_file(undefined1 *param_1,uint param_2,undefined1 *param_3,undefined4 *param_4,
                   undefined4 *param_5)

{
  undefined1 uVar1;
  undefined1 *puVar2;
  int iVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  code *pcVar7;
  int in_t9;
  
  if ((int)param_2 < 0x20) {
    return (undefined1 *)0x0;
  }
  *param_3 = *param_1;
  param_3[1] = param_1[1];
  param_3[2] = param_1[2];
  param_3[3] = param_1[3];
  param_3[4] = param_1[4];
  param_3[5] = param_1[5];
  param_3[6] = param_1[6];
  param_3[7] = param_1[7];
  param_3[8] = param_1[8];
  param_3[9] = param_1[9];
  param_3[10] = param_1[10];
  param_3[0xb] = param_1[0xb];
  param_3[0xc] = param_1[0xc];
  param_3[0xd] = param_1[0xd];
  param_3[0xe] = param_1[0xe];
  param_3[0xf] = param_1[0xf];
  param_3[0x10] = param_1[0x10];
  param_3[0x11] = param_1[0x11];
  param_3[0x12] = param_1[0x12];
  param_3[0x13] = param_1[0x13];
  param_3[0x14] = param_1[0x14];
  param_3[0x15] = param_1[0x15];
  param_3[0x16] = param_1[0x16];
  param_3[0x17] = param_1[0x17];
  param_3[0x18] = param_1[0x18];
  param_3[0x19] = param_1[0x19];
  param_3[0x1a] = param_1[0x1a];
  param_3[0x1b] = param_1[0x1b];
  param_3[0x1c] = param_1[0x1c];
  param_3[0x1d] = param_1[0x1d];
  param_3[0x1e] = param_1[0x1e];
  param_3[0x1f] = param_1[0x1f];
  param_3[0x20] = param_1[0x20];
  param_3[0x21] = param_1[0x21];
  uVar1 = param_1[0x22];
  uVar5 = *(uint *)(param_3 + 4);
  if (*(uint *)(param_3 + 0x10) <= *(uint *)(param_3 + 4)) {
    uVar5 = *(uint *)(param_3 + 0x10);
  }
  param_3[0x22] = uVar1;
  param_3[0x23] = param_1[0x23];
  if (uVar5 < 100) {
    uVar4 = *(undefined4 *)(param_3 + 0x1c);
  }
  else if ((int)param_2 < 100) {
    uVar4 = *(undefined4 *)(param_3 + 0x1c);
  }
  else if (*(uint *)(param_3 + 0x20) < 100) {
    uVar4 = *(undefined4 *)(param_3 + 0x1c);
  }
  else {
    if (*(uint *)(param_3 + 0x20) <= param_2) {
      pcVar7 = (code *)(*(int *)(&UNK_00021cf0 + in_t9) + 0x26d0);
      uVar4 = (*pcVar7)(param_1 + 0x24,param_3 + 0x28,uVar1,param_4,in_t9 + 0x29cc8);
      puVar2 = (undefined1 *)(*pcVar7)(uVar4,param_3 + 0x30);
      param_3[0x38] = *puVar2;
      param_3[0x39] = puVar2[1];
      param_3[0x3a] = puVar2[2];
      param_3[0x3b] = puVar2[3];
      param_3[0x3c] = puVar2[4];
      param_3[0x3d] = puVar2[5];
      param_3[0x3e] = puVar2[6];
      param_3[0x3f] = puVar2[7];
      param_3[0x40] = puVar2[8];
      param_3[0x41] = puVar2[9];
      param_3[0x42] = puVar2[10];
      param_3[0x43] = puVar2[0xb];
      puVar2 = (undefined1 *)(*pcVar7)(puVar2 + 0xc,param_3 + 0x48);
      param_3[0x50] = *puVar2;
      param_3[0x51] = puVar2[1];
      param_3[0x52] = puVar2[2];
      param_3[0x53] = puVar2[3];
      puVar2 = (undefined1 *)(*pcVar7)(puVar2 + 4,param_3 + 0x58);
      param_3[0x60] = *puVar2;
      param_3[0x61] = puVar2[1];
      param_3[0x62] = puVar2[2];
      param_3[99] = puVar2[3];
      puVar2 = (undefined1 *)(*pcVar7)(puVar2 + 4,param_3 + 0x68);
      param_3[0x70] = *puVar2;
      param_3[0x71] = puVar2[1];
      param_3[0x72] = puVar2[2];
      param_3[0x73] = puVar2[3];
      *(undefined4 *)(param_3 + 0x18) = *(undefined4 *)(param_3 + 0x2c);
      *(undefined4 *)(param_3 + 0x1c) = *(undefined4 *)(param_3 + 0x34);
      goto code_r0x00012ae4;
    }
    uVar4 = *(undefined4 *)(param_3 + 0x1c);
  }
  *(undefined4 *)(param_3 + 0x34) = uVar4;
  *(undefined4 *)(param_3 + 0x40) = 0xffffffff;
  *(undefined4 *)(param_3 + 0x38) = 0xffffffff;
  *(undefined4 *)(param_3 + 0x3c) = 0xffffffff;
  *(undefined4 *)(param_3 + 0x20) = 0x20;
  *(undefined4 *)(param_3 + 0x2c) = *(undefined4 *)(param_3 + 0x18);
  *(undefined4 *)(param_3 + 0x28) = 0;
  *(undefined4 *)(param_3 + 0x30) = 0;
  *(undefined4 *)(param_3 + 0x4c) = 0;
  *(undefined4 *)(param_3 + 0x48) = 0;
  *(undefined4 *)(param_3 + 0x50) = 0;
  *(undefined4 *)(param_3 + 0x5c) = 0;
  *(undefined4 *)(param_3 + 0x58) = 0;
  *(undefined4 *)(param_3 + 0x60) = 0;
  *(undefined4 *)(param_3 + 0x6c) = 0;
  *(undefined4 *)(param_3 + 0x68) = 0;
  *(undefined4 *)(param_3 + 0x70) = 0;
code_r0x00012ae4:
  if (param_2 < (uint)(*(int *)(param_3 + 4) + *(int *)(param_3 + 8))) {
    return (undefined1 *)0x0;
  }
  iVar6 = *(int *)(param_3 + 0x14);
  iVar3 = *(int *)(param_3 + 0x10);
  *param_4 = param_1 + *(int *)(param_3 + 4);
  if (param_2 < (uint)(iVar3 + iVar6)) {
    return (undefined1 *)0x0;
  }
  *param_5 = param_1 + iVar3;
  return param_1 + param_2;
}



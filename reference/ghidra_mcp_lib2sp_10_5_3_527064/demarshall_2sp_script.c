
undefined1 *
demarshall_2sp_script
          (undefined1 *param_1,uint param_2,uint *param_3,undefined4 *param_4,undefined4 *param_5,
          undefined4 *param_6)

{
  undefined1 uVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int in_t9;
  
  if (0x33 < (int)param_2) {
    *(undefined1 *)param_3 = *param_1;
    *(undefined1 *)((int)param_3 + 1) = param_1[1];
    *(undefined1 *)((int)param_3 + 2) = param_1[2];
    *(undefined1 *)((int)param_3 + 3) = param_1[3];
    *(undefined1 *)(param_3 + 1) = param_1[4];
    *(undefined1 *)((int)param_3 + 5) = param_1[5];
    *(undefined1 *)((int)param_3 + 6) = param_1[6];
    *(undefined1 *)((int)param_3 + 7) = param_1[7];
    *(undefined1 *)(param_3 + 2) = param_1[8];
    *(undefined1 *)((int)param_3 + 9) = param_1[9];
    *(undefined1 *)((int)param_3 + 10) = param_1[10];
    *(undefined1 *)((int)param_3 + 0xb) = param_1[0xb];
    *(undefined1 *)(param_3 + 3) = param_1[0xc];
    *(undefined1 *)((int)param_3 + 0xd) = param_1[0xd];
    *(undefined1 *)((int)param_3 + 0xe) = param_1[0xe];
    *(undefined1 *)((int)param_3 + 0xf) = param_1[0xf];
    iVar5 = *(int *)(&UNK_00020e1c + in_t9);
    *(undefined1 *)(param_3 + 4) = param_1[0x10];
    *(undefined1 *)((int)param_3 + 0x11) = param_1[0x11];
    *(undefined1 *)((int)param_3 + 0x12) = param_1[0x12];
    *(undefined1 *)((int)param_3 + 0x13) = param_1[0x13];
    *(undefined1 *)(param_3 + 5) = param_1[0x14];
    *(undefined1 *)((int)param_3 + 0x15) = param_1[0x15];
    *(undefined1 *)((int)param_3 + 0x16) = param_1[0x16];
    *(undefined1 *)((int)param_3 + 0x17) = param_1[0x17];
    *(undefined1 *)(param_3 + 6) = param_1[0x18];
    *(undefined1 *)((int)param_3 + 0x19) = param_1[0x19];
    *(undefined1 *)((int)param_3 + 0x1a) = param_1[0x1a];
    *(undefined1 *)((int)param_3 + 0x1b) = param_1[0x1b];
    *(undefined1 *)(param_3 + 7) = param_1[0x1c];
    *(undefined1 *)((int)param_3 + 0x1d) = param_1[0x1d];
    *(undefined1 *)((int)param_3 + 0x1e) = param_1[0x1e];
    *(undefined1 *)((int)param_3 + 0x1f) = param_1[0x1f];
    *(undefined1 *)(param_3 + 8) = param_1[0x20];
    *(undefined1 *)((int)param_3 + 0x21) = param_1[0x21];
    uVar1 = param_1[0x22];
    *(undefined1 *)((int)param_3 + 0x22) = uVar1;
    *(undefined1 *)((int)param_3 + 0x23) = param_1[0x23];
    uVar2 = (*(code *)(iVar5 + 0x26d0))(param_1 + 0x24,param_3 + 10,uVar1,param_4,in_t9 + 0x28df4);
    (*(code *)(iVar5 + 0x26d0))(uVar2,param_3 + 0xc);
    if (0x33 < *param_3) {
      if (param_2 < *param_3) {
        return (undefined1 *)0x0;
      }
      if (param_2 < param_3[2] + param_3[3]) {
        return (undefined1 *)0x0;
      }
      uVar4 = param_3[4];
      if (param_2 < param_3[5] + uVar4) {
        return (undefined1 *)0x0;
      }
      uVar3 = param_3[7];
      if (param_3[8] + uVar3 <= param_2) {
        *param_4 = param_1 + param_3[2];
        *param_5 = param_1 + uVar4;
        *param_6 = param_1 + uVar3;
        return param_1 + param_2;
      }
    }
  }
  return (undefined1 *)0x0;
}



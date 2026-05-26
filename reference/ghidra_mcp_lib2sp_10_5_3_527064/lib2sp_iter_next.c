
void lib2sp_iter_next(int *param_1,int *param_2)

{
  undefined1 *puVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int in_t9;
  
  if (*param_1 != 6) {
    iVar2 = param_1[0x11c];
    iVar4 = param_1[0x11b];
    puVar1 = (undefined1 *)(*param_2 + param_2[2]);
    uVar3 = (iVar4 + iVar2) - (int)puVar1;
    if ((int)uVar3 < 1) {
      *param_2 = 0;
    }
    else {
      if (uVar3 < 8) {
                    /* WARNING: Could not recover jumptable at 0x0001d978. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (**(code **)(&UNK_00016bec + in_t9))(param_1,1,*(int *)(&UNK_00016b3c + in_t9) + 0x33fc);
        return;
      }
      *(undefined1 *)(param_2 + 1) = *puVar1;
      *(undefined1 *)((int)param_2 + 5) = puVar1[1];
      *(undefined1 *)((int)param_2 + 6) = puVar1[2];
      *(undefined1 *)((int)param_2 + 7) = puVar1[3];
      uVar3 = (iVar4 + iVar2) - (int)(puVar1 + 8);
      *(undefined1 *)(param_2 + 2) = puVar1[4];
      *(undefined1 *)((int)param_2 + 9) = puVar1[5];
      *(undefined1 *)((int)param_2 + 10) = puVar1[6];
      *(undefined1 *)((int)param_2 + 0xb) = puVar1[7];
      if (uVar3 < (uint)param_2[2]) {
        (**(code **)(&UNK_00016bec + in_t9))
                  (param_1,1,*(int *)(&UNK_00016b3c + in_t9) + 0x3414,param_2[1],param_2[2],uVar3,
                   &UNK_0001eb18 + in_t9);
      }
      else {
        *param_2 = (int)(puVar1 + 8);
      }
    }
  }
  return;
}



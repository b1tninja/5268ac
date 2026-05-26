
void lib2sp_do_payload_tlv
               (int param_1,uint *param_2,undefined4 param_3,undefined4 param_4,uint param_5,
               uint *param_6,undefined1 *param_7)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  undefined1 *puVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  undefined1 *puVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  int in_t9;
  code *pcVar12;
  undefined1 *puVar13;
  undefined1 *puStack_10c0;
  undefined4 uStack_10bc;
  undefined1 *puStack_10b8;
  undefined1 *puStack_10b4;
  undefined1 auStack_10b0 [8];
  undefined4 uStack_10a8;
  int iStack_1088;
  uint uStack_1084;
  int iStack_1080;
  int iStack_107c;
  undefined1 auStack_1038 [4104];
  int iStack_30;
  int iStack_2c;
  
  uVar1 = *param_2;
  puStack_10c0 = (undefined1 *)0x0;
  uStack_10bc = 0;
  puStack_10b8 = (undefined1 *)0x0;
  puStack_10b4 = (undefined1 *)0x0;
  *param_7 = 0;
  if (uVar1 == 3) {
code_r0x0001e548:
    iVar2 = (**(code **)(&UNK_000160bc + in_t9))
                      (param_3,param_2[1],auStack_10b0,&puStack_10c0,&uStack_10bc);
    if (iVar2 == 0) {
      pcVar12 = *(code **)(&UNK_00016048 + in_t9);
      iVar2 = *(int *)(&UNK_00015f98 + in_t9) + 0x354c;
code_r0x0001e610:
      (*pcVar12)(param_1,9,iVar2);
      return;
    }
    uStack_10a8 = (**(code **)(&UNK_00016070 + in_t9))
                            (param_1,auStack_1038,0x1002,uStack_10a8,puStack_10c0);
    uVar5 = uStack_1084 + iStack_107c;
    uVar1 = (uint)(uVar5 < uStack_1084) + iStack_1088 + iStack_1080;
    puStack_10c0 = auStack_1038;
  }
  else {
    if (uVar1 < 4) {
      uVar5 = 1;
code_r0x0001e540:
      if (uVar1 != uVar5) {
        (**(code **)(&UNK_00016048 + in_t9))
                  (param_1,0xb,*(int *)(&UNK_00015f98 + in_t9) + 0x3618,uVar1);
        return;
      }
      goto code_r0x0001e548;
    }
    uVar5 = 0x2f;
    if (uVar1 != 0x26) goto code_r0x0001e540;
    iVar2 = (**(code **)(&UNK_00016030 + in_t9))
                      (param_3,param_2[1],auStack_10b0,&puStack_10b8,&puStack_10b4,&uStack_10bc);
    if (iVar2 == 0) {
      pcVar12 = *(code **)(&UNK_00016048 + in_t9);
      iVar2 = *(int *)(&UNK_00015f98 + in_t9) + 0x3568;
      goto code_r0x0001e610;
    }
    uVar5 = uStack_1084 + iStack_107c;
    uVar1 = (uint)(uVar5 < uStack_1084) + iStack_1088 + iStack_1080;
  }
  uVar3 = *(uint *)(param_1 + 0x4f4);
  uVar11 = uStack_1084 + *(int *)(param_1 + 0x50c);
  uVar6 = uVar11 - uVar3;
  iVar9 = (uint)(uVar11 < uStack_1084) + iStack_1088 + *(int *)(param_1 + 0x508);
  iVar2 = *(int *)(param_1 + 0x4f0);
  if ((int)uVar6 < 0) {
    (**(code **)(&UNK_00016048 + in_t9))
              (param_1,9,*(int *)(&UNK_00015f98 + in_t9) + 0x3640,iVar9,iVar9,uVar11,iVar2,uVar3);
    return;
  }
  if (uVar6 != 0) {
    if ((int)uVar6 <= (int)param_5) {
      param_5 = uVar6;
    }
    *(uint *)(param_1 + 0x4f4) = param_5 + uVar3;
    *param_6 = param_5;
    *(uint *)(param_1 + 0x4f0) = (uint)(param_5 + uVar3 < param_5) + ((int)param_5 >> 0x1f) + iVar2;
    return;
  }
  iStack_2c = *(int *)(param_1 + 0x4dc);
  iStack_30 = *(int *)(param_1 + 0x4e0);
  if (*(char *)(param_1 + 0x510) == '\0') {
    if ((iStack_1088 == iVar2) && (uStack_1084 == uVar3)) {
      puVar8 = (undefined1 *)*param_2;
    }
    else {
      (**(code **)(&UNK_000160d8 + in_t9))
                (*(int *)(&UNK_00015f98 + in_t9) + 0x3680,*(int *)(&UNK_00015f98 + in_t9) + 0x35e8,
                 0x4cd,*(int *)(&UNK_00015f98 + in_t9) + 0x4170);
      puVar8 = (undefined1 *)*param_2;
    }
    if (puVar8 == (undefined1 *)0x3) {
code_r0x0001e768:
      pcVar12 = *(code **)(&UNK_000160dc + in_t9);
      iVar2 = param_1 + 0x518;
      puVar4 = auStack_10b0;
      puVar13 = puStack_10c0;
code_r0x0001e7a0:
      (*pcVar12)(param_1,iVar2,puVar8,puVar4,puVar13);
      if (*(int *)(param_1 + 8) != 0) {
        return;
      }
      if (*(int *)(param_1 + 0x5c8) != 0) {
        return;
      }
    }
    else {
      if ((undefined1 *)0x3 < puVar8) {
        puVar4 = (undefined1 *)0x2f;
        if (puVar8 != (undefined1 *)0x26) goto code_r0x0001e760;
        pcVar12 = *(code **)(&UNK_000160fc + in_t9);
        iVar2 = param_1 + 0x540;
        puVar8 = auStack_10b0;
        puVar4 = puStack_10b8;
        puVar13 = puStack_10b4;
        goto code_r0x0001e7a0;
      }
      puVar4 = (undefined1 *)0x1;
code_r0x0001e760:
      if (puVar8 == puVar4) goto code_r0x0001e768;
    }
    *(undefined1 *)(param_1 + 0x510) = 1;
  }
  if (iStack_2c - iStack_30 < (int)param_5) {
    param_5 = iStack_2c - iStack_30;
  }
  if ((int)(uVar5 - uVar11) < (int)param_5) {
    param_5 = uVar5 - uVar11;
  }
  (**(code **)(&UNK_00016164 + in_t9))
            (*(int *)(param_1 + 0x4d8) + *(int *)(param_1 + 0x4e0),param_4,param_5);
  uVar11 = *(uint *)(param_1 + 0x4f4);
  uVar7 = *(uint *)(param_1 + 0x50c);
  *(uint *)(param_1 + 0x4e0) = *(int *)(param_1 + 0x4e0) + param_5;
  iVar2 = *(int *)(param_1 + 0x4f0);
  *param_6 = param_5;
  uVar3 = uVar11 + param_5;
  uVar6 = *(uint *)(param_1 + 0x4e0);
  uVar10 = uVar7 + param_5;
  uVar11 = (uint)(uVar3 < uVar11) + iVar2 + ((int)param_5 >> 0x1f);
  *(uint *)(param_1 + 0x508) =
       (uint)(uVar10 < uVar7) + *(int *)(param_1 + 0x508) + ((int)param_5 >> 0x1f);
  *(uint *)(param_1 + 0x50c) = uVar10;
  *(uint *)(param_1 + 0x4f0) = uVar11;
  *(uint *)(param_1 + 0x4f4) = uVar3;
  if (uVar6 < *(uint *)(param_1 + 0x4dc)) {
    if (uVar11 < uVar1) {
      return;
    }
    if ((uVar11 == uVar1) && (uVar3 < uVar5)) {
      return;
    }
  }
  if (uVar6 == 0) {
    uVar3 = *(uint *)(param_1 + 0x4f0);
  }
  else {
    uVar3 = *param_2;
    if (uVar3 == 3) {
code_r0x0001e8c0:
      (**(code **)(&UNK_000160d0 + in_t9))
                (param_1,param_1 + 0x518,auStack_10b0,puStack_10c0,*(undefined4 *)(param_1 + 0x4d8),
                 uVar6);
      iVar2 = *(int *)(param_1 + 8);
    }
    else {
      if (uVar3 < 4) {
        uVar11 = 1;
code_r0x0001e8b8:
        if (uVar3 != uVar11) {
          uVar3 = *(uint *)(param_1 + 0x4f0);
          goto code_r0x0001e934;
        }
        goto code_r0x0001e8c0;
      }
      uVar11 = 0x2f;
      if (uVar3 != 0x26) goto code_r0x0001e8b8;
      (**(code **)(&UNK_00016014 + in_t9))
                (param_1,param_1 + 0x540,auStack_10b0,puStack_10b8,puStack_10b4,
                 *(undefined4 *)(param_1 + 0x4d8),uVar6);
      iVar2 = *(int *)(param_1 + 8);
    }
    if (iVar2 != 0) {
      return;
    }
    if (*(int *)(param_1 + 0x5c8) != 0) {
      return;
    }
    uVar3 = *(uint *)(param_1 + 0x4f0);
  }
code_r0x0001e934:
  *(undefined4 *)(param_1 + 0x4e0) = 0;
  if (uVar3 < uVar1) {
    return;
  }
  if (uVar3 == uVar1) {
    if (*(uint *)(param_1 + 0x4f4) < uVar5) {
      return;
    }
    uVar1 = *param_2;
  }
  else {
    uVar1 = *param_2;
  }
  if (uVar1 == 3) {
code_r0x0001e988:
    (**(code **)(&UNK_00016108 + in_t9))(param_1,param_1 + 0x518,auStack_10b0,puStack_10c0);
    iVar2 = *(int *)(param_1 + 8);
  }
  else {
    if (uVar1 < 4) {
      uVar5 = 1;
code_r0x0001e980:
      if (uVar1 != uVar5) goto code_r0x0001e9e4;
      goto code_r0x0001e988;
    }
    uVar5 = 0x2f;
    if (uVar1 != 0x26) goto code_r0x0001e980;
    (**(code **)(&UNK_00016098 + in_t9))
              (param_1,param_1 + 0x540,auStack_10b0,puStack_10b8,puStack_10b4);
    iVar2 = *(int *)(param_1 + 8);
  }
  if (iVar2 != 0) {
    return;
  }
  if (*(int *)(param_1 + 0x5c8) != 0) {
    return;
  }
code_r0x0001e9e4:
  *(undefined1 *)(param_1 + 0x510) = 0;
  *param_7 = 1;
  *(undefined4 *)(param_1 + 0x50c) = 0;
  *(undefined4 *)(param_1 + 0x508) = 0;
  return;
}



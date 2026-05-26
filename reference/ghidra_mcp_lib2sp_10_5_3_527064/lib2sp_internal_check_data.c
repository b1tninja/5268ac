
void lib2sp_internal_check_data(int param_1,int param_2,int param_3)

{
  char cVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  undefined4 uVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  uint uVar14;
  uint uVar15;
  int in_t9;
  int iVar16;
  code *pcVar17;
  undefined4 uStack_e0;
  undefined4 uStack_dc;
  undefined4 uStack_d8;
  undefined4 uStack_d4;
  undefined1 auStack_d0 [24];
  undefined1 auStack_b8 [12];
  int iStack_ac;
  int iStack_a0;
  int iStack_90;
  uint uStack_8c;
  int iStack_88;
  int iStack_84;
  int iStack_40;
  undefined1 *puStack_3c;
  undefined4 *puStack_38;
  undefined4 *puStack_34;
  undefined4 *puStack_30;
  undefined4 *puStack_2c;
  
  if (*(char *)(param_1 + 0x560) != '\0') {
    return;
  }
  iStack_40 = param_1 + 0x548;
  puStack_3c = auStack_b8;
  puStack_38 = &uStack_dc;
  puStack_34 = &uStack_e0;
  puStack_30 = &uStack_d8;
  puStack_2c = &uStack_d4;
  uStack_e0 = 0;
  uStack_dc = 0;
  uStack_d8 = 0;
  uStack_d4 = 0;
  iVar13 = param_1 + 0x564;
  iVar11 = 0;
code_r0x0001e000:
  iVar6 = *(int *)(param_1 + 0x548);
  do {
    if (iVar6 == 0) {
code_r0x0001e058:
      *(undefined1 *)(param_1 + 0x560) = 1;
      return;
    }
    uVar2 = *(uint *)(param_1 + 0x54c);
    if (uVar2 == 3) {
code_r0x0001e064:
      iVar6 = (**(code **)(&UNK_00016604 + in_t9))
                        (iVar6,*(undefined4 *)(param_1 + 0x550),puStack_3c,puStack_34,puStack_38);
      if (iVar6 == 0) {
        pcVar17 = *(code **)(&UNK_00016590 + in_t9);
        iVar11 = *(int *)(&UNK_000164e0 + in_t9) + 0x354c;
code_r0x0001e0fc:
        uVar9 = 9;
        goto code_r0x0001e41c;
      }
      uVar2 = uStack_8c + iStack_84;
      uVar14 = (uint)(uVar2 < uStack_8c) + iStack_90 + iStack_88;
      iVar6 = iStack_ac;
    }
    else {
      if (uVar2 < 4) {
        if (uVar2 == 0) goto code_r0x0001e058;
        iVar16 = *(int *)(&UNK_000164e0 + in_t9);
        if (uVar2 == 1) goto code_r0x0001e064;
        goto code_r0x0001e464;
      }
      if (uVar2 != 0x26) {
        iVar16 = *(int *)(&UNK_000164e0 + in_t9);
        if (uVar2 == 0x2f) goto code_r0x0001e064;
        goto code_r0x0001e464;
      }
      iVar6 = (**(code **)(&UNK_00016578 + in_t9))
                        (iVar6,*(undefined4 *)(param_1 + 0x550),puStack_3c,puStack_30,puStack_2c,
                         puStack_38);
      if (iVar6 == 0) {
        pcVar17 = *(code **)(&UNK_00016590 + in_t9);
        iVar11 = *(int *)(&UNK_000164e0 + in_t9) + 0x3568;
        goto code_r0x0001e0fc;
      }
      uVar2 = uStack_8c + iStack_84;
      uVar14 = (uint)(uVar2 < uStack_8c) + iStack_90 + iStack_88;
      iVar6 = iStack_a0;
    }
    iVar10 = *(int *)(param_1 + 0x558);
    uVar12 = uStack_8c + *(int *)(param_1 + 0x55c);
    iVar3 = *(int *)(param_1 + 0x4ec);
    iVar4 = *(int *)(param_1 + 0x4e8);
    uVar15 = (uint)(uVar12 < uStack_8c) + iStack_90 + iVar10;
    uVar7 = uVar12 - iVar3;
    iVar16 = (uVar15 - iVar4) - (uint)(uVar12 < uVar7);
    if (iVar16 < 0) {
      (**(code **)(&UNK_00016590 + in_t9))
                (param_1,9,*(int *)(&UNK_000164e0 + in_t9) + 0x3584,iVar10,uVar15,uVar12,iVar4,iVar3
                );
      return;
    }
    if (iVar11 < param_3) {
      if (iVar16 != 0 || uVar7 != 0) {
        uVar2 = param_3 - iVar11;
        iVar6 = (int)uVar2 >> 0x1f;
        if (iVar6 < iVar16) {
code_r0x0001e1f8:
          uVar14 = uVar2 + iVar3;
          uVar7 = uVar2;
          iVar16 = iVar6;
        }
        else if (iVar16 == iVar6) {
          if (uVar2 < uVar7) goto code_r0x0001e1f8;
          uVar14 = uVar7 + iVar3;
        }
        else {
          uVar14 = uVar7 + iVar3;
        }
        *(uint *)(param_1 + 0x4e8) = (uint)(uVar14 < uVar7) + iVar16 + iVar4;
        *(uint *)(param_1 + 0x4ec) = uVar14;
        iVar11 = iVar11 + uVar7;
        goto code_r0x0001e000;
      }
      cVar1 = *(char *)(param_1 + 0x561);
    }
    else {
      if (iVar16 != 0 || uVar7 != 0) {
        return;
      }
      if (uVar14 != uVar15) {
        return;
      }
      if (uVar2 != uVar12) {
        return;
      }
      cVar1 = *(char *)(param_1 + 0x561);
    }
    if (cVar1 == '\0') {
      if (iVar10 != 0 || *(int *)(param_1 + 0x55c) != 0) {
        (**(code **)(&UNK_00016620 + in_t9))
                  (*(int *)(&UNK_000164e0 + in_t9) + 0x35cc,*(int *)(&UNK_000164e0 + in_t9) + 0x35e8
                   ,0x685,*(int *)(&UNK_000164e0 + in_t9) + 0x4154);
      }
      if (iVar6 == 1) {
        pcVar17 = *(code **)(&UNK_00016554 + in_t9);
      }
      else {
        iVar16 = *(int *)(&UNK_000164e0 + in_t9);
        if (iVar6 != 2) goto code_r0x0001e42c;
        pcVar17 = *(code **)(&UNK_00016690 + in_t9);
      }
      (*pcVar17)(iVar13);
      *(undefined1 *)(param_1 + 0x561) = 1;
    }
    uVar12 = uVar2 - uVar12;
    uVar7 = param_3 - iVar11;
    uVar5 = (uVar14 - uVar15) - (uint)(uVar2 < uVar12);
    uVar15 = (int)uVar7 >> 0x1f;
    if ((uVar5 < uVar15) || ((uVar15 == uVar5 && (uVar12 < uVar7)))) {
      uVar7 = uVar12;
      uVar15 = uVar5;
    }
    if (iVar6 == 1) {
      pcVar17 = *(code **)(&UNK_00016660 + in_t9);
    }
    else {
      iVar16 = *(int *)(&UNK_000164e0 + in_t9);
      if (iVar6 != 2) goto code_r0x0001e42c;
      pcVar17 = *(code **)(&UNK_00016588 + in_t9);
    }
    (*pcVar17)(iVar13,param_2 + iVar11,uVar7);
    uVar12 = uVar7 + *(int *)(param_1 + 0x4ec);
    uVar8 = *(uint *)(param_1 + 0x55c) + uVar7;
    uVar5 = (uint)(uVar12 < uVar7) + uVar15 + *(int *)(param_1 + 0x4e8);
    *(uint *)(param_1 + 0x558) =
         (uint)(uVar8 < *(uint *)(param_1 + 0x55c)) + *(int *)(param_1 + 0x558) + uVar15;
    *(uint *)(param_1 + 0x55c) = uVar8;
    iVar11 = iVar11 + uVar7;
    *(uint *)(param_1 + 0x4e8) = uVar5;
    *(uint *)(param_1 + 0x4ec) = uVar12;
    if (uVar5 < uVar14) goto code_r0x0001e000;
    if ((uVar14 != uVar5) || (uVar2 <= uVar12)) break;
    iVar6 = *(int *)(param_1 + 0x548);
  } while( true );
  if (iVar6 == 1) {
    (**(code **)(&UNK_00016538 + in_t9))(auStack_d0,iVar13);
    iVar6 = (**(code **)(&UNK_00016570 + in_t9))(auStack_d0,uStack_dc,0x14);
    if (iVar6 == 0) goto code_r0x0001e44c;
    pcVar17 = *(code **)(&UNK_00016590 + in_t9);
    iVar11 = *(int *)(&UNK_000164e0 + in_t9) + 0x35f0;
  }
  else {
    iVar16 = *(int *)(&UNK_000164e0 + in_t9);
    if (iVar6 != 2) {
code_r0x0001e42c:
      (**(code **)(&UNK_00016590 + in_t9))(param_1,9,iVar16 + 0x18f8,iVar6);
      return;
    }
    (**(code **)(&UNK_00016678 + in_t9))(auStack_d0,iVar13);
    iVar6 = (**(code **)(&UNK_00016570 + in_t9))(auStack_d0,uStack_dc,0x10);
    if (iVar6 == 0) {
code_r0x0001e44c:
      *(undefined4 *)(param_1 + 0x55c) = 0;
      *(undefined4 *)(param_1 + 0x558) = 0;
      *(undefined1 *)(param_1 + 0x561) = 0;
      iVar16 = *(int *)(&UNK_000164e0 + in_t9);
code_r0x0001e464:
      (*(code *)(iVar16 + -0x26f8))(param_1,iStack_40);
      goto code_r0x0001e000;
    }
    pcVar17 = *(code **)(&UNK_00016590 + in_t9);
    iVar11 = *(int *)(&UNK_000164e0 + in_t9) + 0x3604;
  }
  uVar9 = 2;
code_r0x0001e41c:
  (*pcVar17)(param_1,uVar9,iVar11);
  return;
}



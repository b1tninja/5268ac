
int lib2sp_install_data(int *param_1,int param_2,int param_3,int *param_4)

{
  bool bVar1;
  int iVar2;
  int *piVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  int in_t9;
  code *pcVar9;
  int aiStack_38 [2];
  int *piStack_30;
  int iStack_2c;
  
  if (param_1 == (int *)0x0) {
    iVar6 = 0x16;
  }
  else {
    piStack_30 = aiStack_38;
    if (*param_1 != 6) {
      iVar8 = (int)param_1 + 0x419;
      iVar6 = 0;
      uVar7 = param_1[1];
code_r0x000208f0:
      if (uVar7 == 2) {
        piVar3 = (int *)param_1[0x10a];
        iVar5 = param_1[2];
        do {
          if (iVar5 != 0) {
            return iVar5;
          }
          pcVar9 = *(code **)(&UNK_00013ccc + in_t9);
          if (piVar3[1] == 0) {
            piVar3[1] = param_3 - iVar6;
            *piVar3 = param_2 + iVar6;
            iVar6 = param_3;
          }
          iVar5 = (*pcVar9)(piVar3);
          if (iVar5 != 0) {
            if (iVar5 != 4) {
              (*(code *)(*(int *)(&UNK_00013bdc + in_t9) + -0x11c4))
                        (param_1,iVar5,*(int *)(&UNK_00013bdc + in_t9) + 0x3f24);
              goto code_r0x00020da4;
            }
            param_1[1] = 4;
          }
          iVar5 = param_1[0x10c] - piVar3[5];
          if (0 < iVar5) {
            iStack_2c = *param_1;
            iVar2 = (*(code *)(*(int *)(&UNK_00013bdc + in_t9) + -0x840))
                              (param_1,param_1[0x10b],iVar5,piStack_30);
            if (iVar2 != 0) {
              return iVar2;
            }
            if (aiStack_38[0] < iVar5) {
              iVar8 = param_1[0x10b];
            }
            else {
              if (iStack_2c == *param_1) {
                iVar5 = param_1[0x10b];
                piVar3[5] = param_1[0x10c];
                piVar3[4] = iVar5;
                goto code_r0x00020ce0;
              }
              iVar8 = param_1[0x10b];
            }
            iStack_2c = iVar2;
            (**(code **)(&UNK_00013d04 + in_t9))(iVar8,iVar8 + aiStack_38[0],iVar5 - aiStack_38[0]);
            iVar8 = param_1[0x10b];
            iVar6 = iVar6 - piVar3[1];
            piVar3[5] = (aiStack_38[0] + param_1[0x10c]) - iVar5;
            piVar3[4] = iVar8 + (iVar5 - aiStack_38[0]);
            if (iVar6 < 0) {
              pcVar9 = *(code **)(&UNK_00013c8c + in_t9);
              iVar6 = *(int *)(&UNK_00013bdc + in_t9) + 0x3f38;
              goto code_r0x00020cac;
            }
            *piVar3 = 0;
            piVar3[1] = 0;
            goto code_r0x00020ccc;
          }
code_r0x00020ce0:
          bVar1 = iVar6 < param_3;
          if (param_1[1] != 2) goto code_r0x00020db0;
          if (piVar3[1] == 0) goto code_r0x00020cf8;
          iVar5 = param_1[2];
        } while( true );
      }
      if (uVar7 < 3) {
        iVar5 = *(int *)(&UNK_00013bdc + in_t9);
        if (uVar7 != 1) goto code_r0x00020d90;
        iVar2 = 8 - param_1[0x109];
        iVar5 = param_3 - iVar6;
        if (iVar2 < param_3 - iVar6) {
          iVar5 = iVar2;
        }
        (**(code **)(&UNK_00013da8 + in_t9))(iVar8 + param_1[0x109],param_2 + iVar6,iVar5);
        iVar6 = iVar6 + iVar5;
        uVar7 = iVar5 + param_1[0x109];
        param_1[0x109] = uVar7;
        if (7 < uVar7) {
          iVar5 = (**(code **)(&UNK_00013c6c + in_t9))
                            (iVar8,*(int *)(&UNK_00013bdc + in_t9) + 0x3468,8);
          if (iVar5 == 0) {
            iVar5 = *(int *)(&UNK_00013bdc + in_t9);
            param_1[1] = 3;
            iVar5 = (*(code *)(iVar5 + -0x840))(param_1,iVar8,uVar7,piStack_30);
            if (iVar5 != 0) {
              return iVar5;
            }
            bVar1 = iVar6 < param_3;
            if (aiStack_38[0] == param_1[0x109]) goto code_r0x00020db0;
            pcVar9 = *(code **)(&UNK_00013c8c + in_t9);
            iVar6 = *(int *)(&UNK_00013bdc + in_t9) + 0x3e50;
code_r0x00020cac:
            uVar4 = 0xb;
          }
          else {
            iVar5 = (**(code **)(&UNK_00013c6c + in_t9))
                              (iVar8,*(int *)(&UNK_00013bdc + in_t9) + 0x3e70,3);
            if (iVar5 == 0) {
              if (*(char *)(param_1 + 0x10d) == '\0') {
                pcVar9 = *(code **)(&UNK_00013d60 + in_t9);
                param_1[1] = 2;
                piVar3 = (int *)(*pcVar9)(0x30);
                if (piVar3 == (int *)0x0) {
                  pcVar9 = *(code **)(&UNK_00013c8c + in_t9);
                  iVar6 = *(int *)(&UNK_00013bdc + in_t9) + 0x3ea8;
                }
                else {
                  pcVar9 = *(code **)(&UNK_00013d60 + in_t9);
                  param_1[0x10c] = 0xffd0;
                  iVar5 = (*pcVar9)(0xffd0);
                  param_1[0x10b] = iVar5;
                  if (iVar5 != 0) {
                    (**(code **)(&UNK_00013c78 + in_t9))(piVar3,0,0x30);
                    piVar3[9] = 0;
                    pcVar9 = *(code **)(&UNK_00013c04 + in_t9);
                    piVar3[10] = 0;
                    piVar3[0xb] = (int)param_1;
                    iVar5 = (*pcVar9)(piVar3,0,0);
                    if (iVar5 != 0) {
                      (*(code *)(*(int *)(&UNK_00013bdc + in_t9) + -0x11c4))
                                (param_1,iVar5,*(int *)(&UNK_00013bdc + in_t9) + 0x3eec);
                      (**(code **)(&UNK_00013c20 + in_t9))(piVar3);
                      (**(code **)(&UNK_00013c20 + in_t9))(param_1[0x10b]);
                      param_1[0x10b] = 0;
                      goto code_r0x00020da4;
                    }
                    iVar2 = param_1[0x10c];
                    iVar5 = param_1[0x10b];
                    piVar3[1] = param_1[0x109];
                    piVar3[5] = iVar2;
                    piVar3[4] = iVar5;
                    param_1[0x10a] = (int)piVar3;
                    *piVar3 = iVar8;
                    goto code_r0x00020dac;
                  }
                  (**(code **)(&UNK_00013c20 + in_t9))(piVar3);
                  pcVar9 = *(code **)(&UNK_00013c8c + in_t9);
                  iVar6 = *(int *)(&UNK_00013bdc + in_t9) + 0x3ecc;
                }
                uVar4 = 7;
                goto code_r0x00020cb4;
              }
              pcVar9 = *(code **)(&UNK_00013c8c + in_t9);
              iVar6 = *(int *)(&UNK_00013bdc + in_t9) + 0x3e74;
            }
            else {
              pcVar9 = *(code **)(&UNK_00013c8c + in_t9);
              iVar6 = *(int *)(&UNK_00013bdc + in_t9) + 0x3f0c;
            }
            uVar4 = 9;
          }
code_r0x00020cb4:
          (*pcVar9)(param_1,uVar4,iVar6);
          goto code_r0x00020da4;
        }
code_r0x00020dac:
        bVar1 = iVar6 < param_3;
        goto code_r0x00020db0;
      }
      if (uVar7 == 3) {
        iVar8 = (*(code *)(*(int *)(&UNK_00013bdc + in_t9) + -0x840))
                          (param_1,param_2 + iVar6,param_3 - iVar6,aiStack_38);
        if (iVar8 != 0) {
          return iVar8;
        }
        iVar6 = iVar6 + aiStack_38[0];
        iStack_2c = 0;
code_r0x00020ccc:
        *param_4 = iVar6;
        return iStack_2c;
      }
      iVar5 = *(int *)(&UNK_00013bdc + in_t9);
      if (uVar7 != 4) {
code_r0x00020d90:
        (**(code **)(&UNK_00013c8c + in_t9))(param_1,0xb,iVar5 + 0x3f5c);
code_r0x00020da4:
        return param_1[2];
      }
      iVar5 = param_1[0x10a];
      iVar8 = param_1[0x10c] - *(int *)(iVar5 + 0x14);
      iVar6 = param_3;
      if (0 < iVar8) {
        iVar6 = (*(code *)(*(int *)(&UNK_00013bdc + in_t9) + -0x840))
                          (param_1,param_1[0x10b],iVar8,aiStack_38);
        if (iVar6 != 0) {
          return iVar6;
        }
        iVar6 = param_1[0x10b];
        if (iVar8 < aiStack_38[0]) {
          iVar8 = param_1[0x10c];
          *(int *)(iVar5 + 0x10) = iVar6;
          *(int *)(iVar5 + 0x14) = iVar8;
          iVar6 = param_3;
        }
        else {
          (**(code **)(&UNK_00013d04 + in_t9))(iVar6,iVar6 + aiStack_38[0],iVar8 - aiStack_38[0]);
          iVar6 = param_1[0x10c];
          *(int *)(iVar5 + 0x10) = param_1[0x10b] + (iVar8 - aiStack_38[0]);
          *(int *)(iVar5 + 0x14) = (aiStack_38[0] + iVar6) - iVar8;
          iVar6 = param_3;
        }
      }
code_r0x00020db8:
      *param_4 = iVar6;
      return 0;
    }
    iVar6 = param_1[2];
    if (iVar6 == 0) {
      iVar6 = 0x16;
    }
  }
  return iVar6;
code_r0x00020cf8:
  bVar1 = iVar6 < param_3;
code_r0x00020db0:
  if (!bVar1) goto code_r0x00020db8;
  uVar7 = param_1[1];
  goto code_r0x000208f0;
}



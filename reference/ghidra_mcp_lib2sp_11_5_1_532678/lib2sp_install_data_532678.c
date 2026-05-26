/* Ghidra MCP decompile — lib2sp_install_data @ 0x00020ae0 (532678 lib2sp.so.0.0.0)
 * Magic scan: memcpy(ctx+0x419, buf, n) with n capped by 8 - ctx[0x109].
 * BZ2: malloc(0xffd0) + BZ2_bzDecompress when magic is BZh (state 2).
 * State 3+: lib2sp_install_2sp_data on decompressed/plain buffer.
 */

int lib2sp_install_data(int *param_1,int param_2,int param_3,int *param_4)

{
  bool bVar1;
  int iVar2;
  int *piVar3;
  undefined4 uVar4;
  undefined *puVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int local_38 [2];
  int local_30;
  
  iVar7 = 0x16;
  if (param_1 != (int *)0x0) {
    iVar7 = 0;
    if (*param_1 != 6) {
      uVar6 = param_1[1];
      while (uVar6 == 2) {
        piVar3 = (int *)param_1[0x10a];
        iVar2 = param_1[2];
        while( true ) {
          puVar5 = PTR_BZ2_bzDecompress_00036884;
          if (iVar2 != 0) {
            return iVar2;
          }
          if (piVar3[1] == 0) {
            *piVar3 = param_2 + iVar7;
            piVar3[1] = param_3 - iVar7;
            iVar7 = param_3;
          }
          iVar2 = (*(code *)puVar5)(piVar3);
          if (iVar2 != 0) {
            if (iVar2 != 4) {
              handle_bz2_error(param_1,iVar2,PTR_LAB_00036774 + 0x614c);
              goto LAB_00021048;
            }
            param_1[1] = 4;
          }
          iVar2 = param_1[0x10c] - piVar3[5];
          if (0 < iVar2) {
            local_30 = *param_1;
            iVar9 = lib2sp_install_2sp_data(param_1,param_1[0x10b],iVar2,local_38);
            if (iVar9 != 0) goto LAB_00020fa8;
            iVar9 = param_1[0x10b];
            if ((local_38[0] < iVar2) || (local_30 != *param_1)) {
              (*(code *)PTR_memmove_000368c0)(iVar9,iVar9 + local_38[0],iVar2 - local_38[0]);
              iVar9 = param_1[0x10b];
              piVar3[5] = (local_38[0] + param_1[0x10c]) - iVar2;
              iVar7 = iVar7 - piVar3[1];
              piVar3[4] = iVar9 + (iVar2 - local_38[0]);
              if (-1 < iVar7) {
                piVar3[1] = 0;
                *piVar3 = 0;
                goto LAB_00020f3c;
              }
              uVar4 = 0xb;
              puVar5 = PTR_LAB_00036774 + 0x6160;
              goto LAB_00020c94;
            }
            iVar2 = param_1[0x10c];
            piVar3[4] = iVar9;
            piVar3[5] = iVar2;
          }
          bVar1 = iVar7 < param_3;
          if (param_1[1] != 2) goto LAB_00021054;
          if (piVar3[1] == 0) break;
          iVar2 = param_1[2];
        }
        bVar1 = iVar7 < param_3;
LAB_00021054:
        if (!bVar1) goto LAB_0002105c;
        uVar6 = param_1[1];
      }
      if (uVar6 < 3) {
        if (uVar6 == 1) {
          iVar2 = 8 - param_1[0x109];
          if (param_3 - iVar7 <= iVar2) {
            iVar2 = param_3 - iVar7;
          }
          iVar9 = (int)param_1 + 0x419;
          (*(code *)PTR_memcpy_00036978)(iVar9 + param_1[0x109],param_2 + iVar7,iVar2);
          uVar6 = iVar2 + param_1[0x109];
          param_1[0x109] = uVar6;
          iVar7 = iVar7 + iVar2;
          if (7 < uVar6) {
            iVar2 = (*(code *)PTR_memcmp_00036810)(iVar9,PTR_LAB_00036774 + 0x5154,8);
            if (iVar2 == 0) {
              param_1[1] = 3;
              iVar9 = lib2sp_install_2sp_data(param_1,iVar9,uVar6,local_38);
              if (iVar9 != 0) goto LAB_00020fa8;
              bVar1 = iVar7 < param_3;
              if (local_38[0] == param_1[0x109]) goto LAB_00021054;
              uVar4 = 0xb;
              puVar5 = PTR_LAB_00036774 + 0x6078;
            }
            else {
              iVar2 = (*(code *)PTR_memcmp_00036810)(iVar9,PTR_LAB_00036774 + 0x6098,3);
              puVar5 = PTR_malloc_0003692c;
              if (iVar2 == 0) {
                if (*(char *)(param_1 + 0x10d) == '\0') {
                  param_1[1] = 2;
                  piVar3 = (int *)(*(code *)puVar5)(0x30);
                  puVar5 = PTR_malloc_0003692c;
                  if (piVar3 == (int *)0x0) {
                    uVar4 = 7;
                    puVar5 = PTR_LAB_00036774 + 0x60d0;
                  }
                  else {
                    param_1[0x10c] = 0xffd0;
                    iVar2 = (*(code *)puVar5)(0xffd0);
                    param_1[0x10b] = iVar2;
                    if (iVar2 != 0) {
                      (*(code *)PTR_memset_00036820)(piVar3,0,0x30);
                      piVar3[9] = 0;
                      puVar5 = PTR_BZ2_bzDecompressInit_000367a0;
                      piVar3[10] = 0;
                      piVar3[0xb] = (int)param_1;
                      iVar2 = (*(code *)puVar5)(piVar3,0,0);
                      if (iVar2 != 0) {
                        handle_bz2_error(param_1,iVar2,PTR_LAB_00036774 + 0x6114);
                        (*(code *)PTR_free_000367bc)(piVar3);
                        (*(code *)PTR_free_000367bc)(param_1[0x10b]);
                        param_1[0x10b] = 0;
                        goto LAB_00021048;
                      }
                      iVar2 = param_1[0x109];
                      *piVar3 = iVar9;
                      piVar3[1] = iVar2;
                      piVar3[5] = param_1[0x10c];
                      piVar3[4] = param_1[0x10b];
                      param_1[0x10a] = (int)piVar3;
                      goto LAB_00021050;
                    }
                    (*(code *)PTR_free_000367bc)();
                    uVar4 = 7;
                    puVar5 = PTR_LAB_00036774 + 0x60f4;
                  }
                }
                else {
                  uVar4 = 9;
                  puVar5 = PTR_LAB_00036774 + 0x609c;
                }
              }
              else {
                uVar4 = 9;
                puVar5 = PTR_LAB_00036774 + 0x6134;
              }
            }
LAB_00020c94:
            (*(code *)PTR_lib2sp_set_error_0003683c)(param_1,uVar4,puVar5);
            goto LAB_00021048;
          }
LAB_00021050:
          bVar1 = iVar7 < param_3;
          goto LAB_00021054;
        }
      }
      else {
        if (uVar6 == 3) {
          iVar9 = lib2sp_install_2sp_data(param_1,param_2 + iVar7,param_3 - iVar7,local_38);
          if (iVar9 == 0) {
            iVar7 = iVar7 + local_38[0];
LAB_00020f3c:
            *param_4 = iVar7;
            return 0;
          }
LAB_00020fa8:
          (*(code *)PTR_lib2sp_log_00036798)
                    (param_1,3,PTR_LAB_00036774 + 0x5db0,PTR_LAB_00036774 + 0x63d4,*param_1,iVar9);
          return iVar9;
        }
        if (uVar6 == 4) {
          iVar8 = param_1[0x10a];
          iVar2 = param_1[0x10c] - *(int *)(iVar8 + 0x14);
          iVar7 = param_3;
          if (0 < iVar2) {
            iVar9 = lib2sp_install_2sp_data(param_1,param_1[0x10b],iVar2,local_38);
            if (iVar9 != 0) goto LAB_00020fa8;
            iVar7 = param_1[0x10b];
            if (iVar2 < local_38[0]) {
              iVar2 = param_1[0x10c];
              *(int *)(iVar8 + 0x10) = iVar7;
              *(int *)(iVar8 + 0x14) = iVar2;
              iVar7 = param_3;
            }
            else {
              (*(code *)PTR_memmove_000368c0)(iVar7,iVar7 + local_38[0],iVar2 - local_38[0]);
              iVar7 = param_1[0x10b];
              *(int *)(iVar8 + 0x14) = (local_38[0] + param_1[0x10c]) - iVar2;
              *(int *)(iVar8 + 0x10) = iVar7 + (iVar2 - local_38[0]);
              iVar7 = param_3;
            }
          }
LAB_0002105c:
          *param_4 = iVar7;
          return 0;
        }
      }
      (*(code *)PTR_lib2sp_set_error_0003683c)(param_1,0xb,PTR_LAB_00036774 + 0x6184);
LAB_00021048:
      return param_1[2];
    }
    iVar7 = param_1[2];
    if (iVar7 == 0) {
      iVar7 = 0x16;
    }
  }
  return iVar7;
}

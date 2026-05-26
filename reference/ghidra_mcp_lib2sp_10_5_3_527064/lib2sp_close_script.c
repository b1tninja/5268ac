
void lib2sp_close_script(int param_1,int *param_2,int param_3,undefined4 param_4,undefined4 param_5)

{
  undefined1 uVar1;
  undefined1 uVar2;
  undefined1 *puVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  undefined *puVar13;
  
  if (param_2[1] < 1) {
    (*(code *)PTR_lib2sp_log_00034464)
              (param_1,6,PTR_LAB_00034444 + 0x1520,*(undefined4 *)(param_3 + 0x14),param_5);
    (*(code *)(PTR_00034448 + 0x4f18))(param_1,param_5,*(undefined4 *)(param_3 + 0x14));
    iVar8 = *param_2;
    if (iVar8 == 0) goto LAB_0001564c;
  }
  else {
    iVar8 = (*(code *)PTR_realloc_00034604)(*param_2,param_2[1] + 2);
    *param_2 = iVar8;
    if (iVar8 == 0) {
      (*(code *)PTR_lib2sp_set_error_000344f4)(param_1,7,PTR_LAB_00034444 + 0x1540);
      param_2[1] = 0;
      return;
    }
    iVar9 = param_2[1];
    uVar1 = PTR_LAB_00034444[0x1cfd];
    uVar2 = PTR_LAB_00034444[0x1cfc];
    param_2[1] = iVar9 + 2;
    iVar7 = *(int *)(param_3 + 0x14);
    puVar3 = (undefined1 *)(iVar8 + iVar9);
    puVar3[1] = uVar1;
    *puVar3 = uVar2;
    if (iVar7 == 0) {
      iVar8 = (*(code *)PTR_tu_uptime_msecs_000345b0)();
      (*(code *)PTR_lib2sp_log_00034464)
                (param_1,6,PTR_LAB_00034444 + 0x15ec,*(undefined4 *)(param_3 + 0xc),param_4);
      iVar7 = (*(code *)(PTR_00034448 + 0x50b4))(param_1,*param_2,param_2[1]);
      (*(code *)PTR_free_00034488)(*param_2);
      param_2[1] = 0;
      *param_2 = 0;
      uVar5 = *(undefined4 *)(param_3 + 0xc);
      if (iVar7 == 0) {
        iVar7 = (*(code *)PTR_tu_uptime_msecs_000345b0)();
        (*(code *)PTR_lib2sp_log_00034464)
                  (param_1,6,PTR_LAB_00034444 + 0x1604,uVar5,param_4,iVar7 - iVar8);
        return;
      }
                    /* WARNING: Could not recover jumptable at 0x00015754. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      (*(code *)PTR_lib2sp_set_error_000344f4)(param_1,8,PTR_LAB_00034444 + 0x1624);
      return;
    }
    (*(code *)PTR_lib2sp_log_00034464)
              (param_1,6,PTR_LAB_00034444 + 0x1568,*(undefined4 *)(param_3 + 0xc),param_4,iVar7,
               param_5);
    iVar7 = *(int *)(param_3 + 0xc);
    iVar11 = *(int *)(param_3 + 0x14);
    iVar8 = *param_2;
    uVar12 = *(uint *)(param_3 + 4);
    iVar9 = param_2[1];
    (*(code *)(PTR_00034448 + 0x4f18))(param_1,param_5,iVar11);
    puVar4 = (undefined4 *)(*(code *)PTR_malloc_000345c8)(0x18);
    puVar13 = PTR_malloc_000345c8;
    if (puVar4 == (undefined4 *)0x0) {
      (*(code *)PTR_lib2sp_set_error_000344f4)(param_1,7,PTR_LAB_00034444 + 0x159c);
    }
    else {
      iVar10 = iVar7 + 1;
      *puVar4 = 0;
      puVar4[1] = 0;
      puVar4[2] = 0;
      puVar4[3] = 0;
      puVar4[4] = 0;
      puVar4[5] = 0;
      uVar5 = (*(code *)puVar13)(iVar10);
      puVar13 = PTR_malloc_000345c8;
      puVar4[1] = uVar5;
      uVar5 = (*(code *)puVar13)(iVar11 + 1);
      puVar13 = PTR_malloc_000345c8;
      puVar4[2] = uVar5;
      iVar6 = (*(code *)puVar13)(iVar9);
      uVar12 = uVar12 & 1;
      puVar4[3] = iVar6;
      *(char *)(puVar4 + 5) = (char)uVar12;
      if (((puVar4[1] == 0) || (puVar4[2] == 0)) || (iVar6 == 0)) {
        (*(code *)PTR_lib2sp_set_error_000344f4)(param_1,7,PTR_LAB_00034444 + 0x15bc);
        if (puVar4[1] != 0) {
          (*(code *)PTR_free_00034488)();
        }
        if (puVar4[2] != 0) {
          (*(code *)PTR_free_00034488)();
        }
        if (puVar4[3] != 0) {
          (*(code *)PTR_free_00034488)();
        }
        (*(code *)PTR_free_00034488)(puVar4);
      }
      else {
        puVar13 = PTR_LAB_00034444 + 0x1460;
        (*(code *)PTR_snprintf_000345ac)(puVar4[1],iVar10,puVar13,iVar7,param_4);
        (*(code *)PTR_snprintf_000345ac)(puVar4[2],iVar11 + 1,puVar13,iVar11,param_5);
        if (uVar12 != 0) {
          uVar5 = puVar4[2];
          iVar7 = (*(code *)PTR_strcmp_000344a0)(uVar5,PTR_LAB_00034444 + 0x3740);
          if ((iVar7 == 0) ||
             (iVar7 = (*(code *)PTR_strcmp_000344a0)(uVar5,PTR_LAB_00034444 + 0x15e4), iVar7 == 0))
          {
            *(undefined1 *)(puVar4 + 5) = 0;
          }
        }
        (*(code *)PTR_memcpy_00034610)(puVar4[3],iVar8,iVar9);
        uVar5 = *(undefined4 *)(param_1 + 0x5c4);
        *(undefined4 **)(param_1 + 0x5c4) = puVar4;
        puVar4[4] = iVar9;
        *puVar4 = uVar5;
      }
    }
    iVar8 = *param_2;
  }
  (*(code *)PTR_free_00034488)(iVar8);
LAB_0001564c:
  param_2[1] = 0;
  *param_2 = 0;
  return;
}



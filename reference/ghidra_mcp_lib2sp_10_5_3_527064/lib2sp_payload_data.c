
void lib2sp_payload_data(int *param_1,undefined4 param_2,undefined4 param_3,int *param_4)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined *puVar4;
  int iVar5;
  undefined1 local_1c0 [4];
  int local_1bc;
  undefined1 auStack_1b8 [4];
  undefined1 auStack_1b4 [4];
  undefined1 auStack_1b0 [8];
  undefined1 auStack_1a8 [4];
  uint local_1a4;
  int local_194;
  uint local_170 [22];
  uint local_118 [22];
  uint local_c0 [30];
  uint *local_48;
  uint *local_44;
  uint *local_40;
  undefined1 *local_3c;
  undefined1 *local_38;
  int *local_34;
  undefined1 *local_30;
  
  local_48 = local_118;
  local_44 = local_170;
  local_40 = local_c0;
  local_3c = auStack_1a8;
  local_38 = auStack_1b0;
  local_34 = &local_1bc;
  local_30 = local_1c0;
  local_1bc = 0;
  do {
    if (local_1bc != 0) {
LAB_0001ee08:
      *param_4 = local_1bc;
      return;
    }
    iVar5 = param_1[0x13e];
    if (iVar5 == 0) {
      *param_1 = 5;
      *param_4 = 0;
      return;
    }
    uVar1 = param_1[0x13f];
    if (uVar1 < 0x29) {
      if ((uVar1 < 0x27) && (uVar1 != 5)) {
        if (uVar1 < 6) {
          if ((uVar1 == 1) || (uVar2 = 0, uVar1 == 3)) goto LAB_0001eb7c;
        }
        else if (uVar1 == 8) {
LAB_0001ebf4:
          iVar5 = (*(code *)PTR_demarshall_2sp_move_00034570)
                            (iVar5,param_1[0x140],local_48,auStack_1b4,auStack_1b8);
          uVar2 = local_118[0];
          if (iVar5 == 0) {
            puVar4 = PTR_LAB_00034444 + 0x2160;
            goto LAB_0001ec24;
          }
        }
        else if (uVar1 == 0x26) {
          iVar5 = (*(code *)PTR_demarshall_2sp_script_000344dc)
                            (iVar5,param_1[0x140],local_3c,auStack_1b8,auStack_1b4,local_38);
          if (iVar5 == 0) {
            puVar4 = PTR_LAB_00034444 + 0x3568;
            goto LAB_0001ec70;
          }
          uVar2 = local_1a4;
          if (local_194 != 0) {
            uVar2 = 0;
          }
        }
        else {
          uVar2 = 0;
          if (uVar1 == 7) goto LAB_0001ebb8;
        }
      }
      else {
LAB_0001ebb8:
        iVar5 = (*(code *)PTR_demarshall_2sp_path_0003460c)
                          (iVar5,param_1[0x140],local_44,auStack_1b4);
        uVar2 = local_170[0];
        if (iVar5 == 0) {
          puVar4 = PTR_LAB_00034444 + 0x1798;
LAB_0001ec24:
          uVar3 = 1;
LAB_0001ec74:
          (*(code *)PTR_lib2sp_set_error_000344f4)(param_1,uVar3,puVar4);
          return;
        }
      }
    }
    else if (uVar1 < 0x2e) {
      if (0x2b < uVar1) goto LAB_0001ebb8;
      uVar2 = 0;
      if (0x29 < uVar1) goto LAB_0001ebf4;
    }
    else {
      uVar2 = 0;
      if (uVar1 == 0x2f) {
LAB_0001eb7c:
        iVar5 = (*(code *)PTR_demarshall_2sp_file_00034568)
                          (iVar5,param_1[0x140],local_40,auStack_1b8,auStack_1b4);
        uVar2 = local_c0[0];
        if (iVar5 == 0) {
          puVar4 = PTR_LAB_00034444 + 0x354c;
LAB_0001ec70:
          uVar3 = 9;
          goto LAB_0001ec74;
        }
      }
    }
    if (*param_1 == 3) {
      if ((uVar2 & 1) == 0) {
        uVar1 = param_1[0x13f];
        goto LAB_0001ecb4;
      }
LAB_0001eddc:
      *param_1 = 4;
      goto LAB_0001ee08;
    }
    uVar1 = param_1[0x13f];
LAB_0001ecb4:
    if (uVar1 < 0x30) {
                    /* WARNING: Could not emulate address calculation at 0x0001eccc */
                    /* WARNING: Treating indirect jump as call */
      (*(code *)(&_gp_1 + *(int *)(PTR_LAB_00034444 + uVar1 * 4 + 0x3f80)))();
      return;
    }
    if (param_1[2] != 0) goto LAB_0001ee08;
    if (param_1[0x172] != 0) goto LAB_0001eddc;
    (*(code *)(PTR_LAB_00034444 + -0x26f8))(param_1,param_1 + 0x13e);
  } while( true );
}



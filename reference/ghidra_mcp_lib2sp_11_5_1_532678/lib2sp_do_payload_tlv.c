
void lib2sp_do_payload_tlv
               (int param_1,uint *param_2,undefined4 param_3,undefined4 param_4,uint param_5,
               uint *param_6,undefined1 *param_7)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined *puVar6;
  uint uVar7;
  undefined1 *puVar8;
  undefined *puVar9;
  uint uVar10;
  undefined1 *puVar11;
  int iVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  code *pcVar16;
  undefined4 local_10c8;
  undefined4 local_10c4;
  undefined4 local_10c0;
  undefined1 *local_10bc;
  undefined1 auStack_10b8 [8];
  undefined4 local_10b0;
  int local_1090;
  uint local_108c;
  int local_1088;
  int local_1084;
  undefined1 auStack_1040 [4104];
  int local_38;
  int local_34;
  int local_30;
  
  puVar9 = (undefined *)*param_2;
  local_10bc = (undefined1 *)0x0;
  local_10c0 = 0;
  local_10c4 = 0;
  local_10c8 = 0;
  *param_7 = 0;
  if (puVar9 != (undefined *)0x26) {
    if (puVar9 < (undefined *)0x27) {
      if ((puVar9 != (undefined *)0x1) && (puVar9 != (undefined *)0x3)) {
LAB_0001e988:
        puVar6 = PTR_LAB_00036774 + 0x5594;
        goto LAB_0001ee74;
      }
LAB_0001e8b4:
      iVar2 = (*(code *)PTR_demarshall_2sp_file_000368bc)
                        (param_3,param_2[1],auStack_10b8,&local_10bc,&local_10c0);
      if (iVar2 == 0) {
        puVar9 = PTR_LAB_00036774 + 0x52b8;
        goto LAB_0001e880;
      }
      local_10b0 = (*(code *)PTR_lib2sp_mkpath_0003686c)
                             (param_1,auStack_1040,0x1002,local_10b0,local_10bc);
      local_10bc = auStack_1040;
      goto LAB_0001e964;
    }
    if (puVar9 == (undefined *)0x2f) goto LAB_0001e8b4;
    if (puVar9 != (undefined *)0x3e8) goto LAB_0001e988;
    iVar2 = *(int *)(param_1 + 0x574);
    if (iVar2 != 0) {
      iVar12 = (*(code *)PTR_demarshall_2sp_dpi_sig_000368ac)(param_3,param_2[1],param_1 + 0x568);
      if (iVar12 == 0) {
        puVar9 = PTR_LAB_00036774 + 0x5400;
        goto LAB_0001e880;
      }
      local_10bc = (undefined1 *)(iVar2 + 0x11c);
      uVar14 = *(uint *)(param_1 + 0x468);
      uVar15 = 0;
      uVar13 = 0;
      iVar2 = 0;
      goto LAB_0001e998;
    }
LAB_0001eb00:
    puVar9 = PTR_LAB_00036774 + 0x53c8;
LAB_0001e880:
    (*(code *)PTR_lib2sp_set_error_0003683c)(param_1,9,puVar9);
    return;
  }
  iVar2 = (*(code *)PTR_demarshall_2sp_script_0003681c)
                    (param_3,param_2[1],auStack_10b8,&local_10c4,&local_10c8,&local_10c0);
  if (iVar2 == 0) {
    puVar9 = PTR_LAB_00036774 + 0x538c;
    goto LAB_0001e880;
  }
LAB_0001e964:
  uVar14 = local_108c + local_1084;
  uVar15 = (uint)(uVar14 < local_108c) + local_1090 + local_1088;
  iVar2 = local_1090;
  uVar13 = local_108c;
LAB_0001e998:
  puVar6 = PTR_lib2sp_log_00036798;
  puVar9 = PTR_LAB_00036774;
  local_38 = uVar13 + *(int *)(param_1 + 0x52c);
  uVar4 = *(uint *)(param_1 + 0x514);
  uVar3 = local_38 - uVar4;
  if ((int)uVar3 < 0) {
    (*(code *)PTR_lib2sp_set_error_0003683c)(param_1,9,PTR_LAB_00036774 + 0x55bc);
    return;
  }
  if (uVar3 != 0) {
    if ((int)param_5 < (int)uVar3) {
      uVar3 = param_5;
    }
    uVar4 = uVar3 + uVar4;
    iVar2 = (uint)(uVar4 < uVar3) + ((int)uVar3 >> 0x1f) + *(int *)(param_1 + 0x510);
    *(int *)(param_1 + 0x510) = iVar2;
    *(uint *)(param_1 + 0x514) = uVar4;
    *param_6 = uVar3;
    (*(code *)puVar6)(param_1,6,puVar9 + 0x55fc,puVar9 + 0x6414,iVar2,uVar4,uVar3,param_5);
    return;
  }
  local_34 = *(int *)(param_1 + 0x4fc);
  local_30 = *(int *)(param_1 + 0x500);
  if (*(char *)(param_1 + 0x530) == '\0') {
    if ((iVar2 == *(int *)(param_1 + 0x510)) && (uVar13 == uVar4)) {
      uVar3 = *param_2;
    }
    else {
      uVar3 = 0x53e;
      (*(code *)PTR___assert_000368dc)
                (PTR_LAB_00036774 + 0x5634,PTR_LAB_00036774 + 0x554c,0x53e,PTR_LAB_00036774 + 0x642c
                );
    }
    if (uVar3 == 0x26) {
      iVar12 = param_1 + 0x560;
      pcVar16 = (code *)PTR_lib2sp_open_script_00036908;
LAB_0001eb48:
      (*pcVar16)(param_1,iVar12);
      if (*(int *)(param_1 + 8) != 0) {
        return;
      }
      if (*(int *)(param_1 + 0x608) != 0) {
        return;
      }
    }
    else if (uVar3 < 0x27) {
      if ((uVar3 == 1) || (uVar3 == 3)) goto LAB_0001eb34;
    }
    else {
      if (uVar3 == 0x2f) {
LAB_0001eb34:
        iVar12 = param_1 + 0x538;
        pcVar16 = (code *)PTR_lib2sp_open_file_000368e0;
        goto LAB_0001eb48;
      }
      if (uVar3 == 1000) {
        if (*(int *)(param_1 + 0x574) == 0) goto LAB_0001eb00;
        iVar12 = param_1 + 0x538;
        pcVar16 = (code *)PTR_lib2sp_open_dpi_sig_00036918;
        goto LAB_0001eb48;
      }
    }
    *(undefined1 *)(param_1 + 0x530) = 1;
  }
  if (local_34 - local_30 < (int)param_5) {
    param_5 = local_34 - local_30;
  }
  if ((int)(uVar14 - local_38) < (int)param_5) {
    param_5 = uVar14 - local_38;
  }
  (*(code *)PTR_memcpy_00036978)
            (*(int *)(param_1 + 0x4f8) + *(int *)(param_1 + 0x500),param_4,param_5);
  uVar5 = param_5 + *(int *)(param_1 + 0x514);
  *(uint *)(param_1 + 0x500) = *(int *)(param_1 + 0x500) + param_5;
  uVar4 = (uint)(uVar5 < param_5) + ((int)param_5 >> 0x1f) + *(int *)(param_1 + 0x510);
  uVar3 = *(uint *)(param_1 + 0x52c) + param_5;
  *(uint *)(param_1 + 0x528) =
       (uint)(uVar3 < *(uint *)(param_1 + 0x52c)) +
       *(int *)(param_1 + 0x528) + ((int)param_5 >> 0x1f);
  *(uint *)(param_1 + 0x52c) = uVar3;
  *(uint *)(param_1 + 0x510) = uVar4;
  *(uint *)(param_1 + 0x514) = uVar5;
  *param_6 = param_5;
  uVar3 = *param_2;
  if (uVar3 == 1000) {
    uVar7 = uVar14 - uVar13;
    uVar10 = (uVar15 - iVar2) - (uint)(uVar14 < uVar7);
    bVar1 = true;
    if (uVar10 <= uVar4) {
      if (uVar10 == uVar4) {
LAB_0001ec80:
        bVar1 = true;
        if (uVar5 < uVar7) goto LAB_0001ec90;
      }
      bVar1 = false;
    }
  }
  else {
    bVar1 = true;
    if (uVar15 <= uVar4) {
      uVar7 = uVar14;
      if (uVar15 == uVar4) goto LAB_0001ec80;
      bVar1 = false;
    }
  }
LAB_0001ec90:
  uVar4 = *(uint *)(param_1 + 0x500);
  if ((uVar4 < *(uint *)(param_1 + 0x4fc)) && (bVar1)) {
    return;
  }
  if (uVar4 == 0) {
    uVar3 = *param_2;
  }
  else {
    if (uVar3 == 0x26) {
      (*(code *)PTR_lib2sp_write_script_000367f4)
                (param_1,param_1 + 0x560,auStack_10b8,local_10c4,local_10c8,
                 *(undefined4 *)(param_1 + 0x4f8),uVar4);
    }
    else {
      if (uVar3 < 0x27) {
        if (uVar3 == 1) goto LAB_0001ed24;
        if (uVar3 != 3) {
          uVar3 = *param_2;
          goto LAB_0001eda4;
        }
        uVar3 = *(uint *)(param_1 + 0x4f8);
LAB_0001ed28:
        puVar8 = auStack_10b8;
        puVar11 = local_10bc;
        pcVar16 = (code *)PTR_lib2sp_write_file_000368d0;
        uVar5 = uVar4;
      }
      else {
        if (uVar3 == 0x2f) {
LAB_0001ed24:
          uVar3 = *(uint *)(param_1 + 0x4f8);
          goto LAB_0001ed28;
        }
        if (uVar3 != 1000) {
          uVar3 = *param_2;
          goto LAB_0001eda4;
        }
        if (*(int *)(param_1 + 0x574) == 0) goto LAB_0001eb00;
        uVar5 = *(int *)(param_1 + 0x574) + 0x11c;
        puVar11 = *(undefined1 **)(param_1 + 0x4f8);
        puVar8 = (undefined1 *)(param_1 + 0x568);
        pcVar16 = (code *)PTR_lib2sp_write_dpi_sig_00036808;
        uVar3 = uVar4;
      }
      (*pcVar16)(param_1,param_1 + 0x538,puVar8,puVar11,uVar3,uVar5);
    }
    if (*(int *)(param_1 + 8) != 0) {
      return;
    }
    if (*(int *)(param_1 + 0x608) != 0) {
      return;
    }
    uVar3 = *param_2;
  }
LAB_0001eda4:
  *(undefined4 *)(param_1 + 0x500) = 0;
  uVar4 = *(uint *)(param_1 + 0x510);
  if (uVar3 == 1000) {
    uVar15 = (uVar15 - iVar2) - (uint)(uVar14 < uVar14 - uVar13);
    if (uVar4 < uVar15) {
      return;
    }
    if (uVar4 == uVar15) {
      if (*(uint *)(param_1 + 0x514) < uVar14 - uVar13) {
        return;
      }
      iVar2 = *(int *)(param_1 + 0x574);
    }
    else {
      iVar2 = *(int *)(param_1 + 0x574);
    }
LAB_0001ee54:
    if (iVar2 == 0) {
      puVar6 = PTR_LAB_00036774 + 0x4068;
      puVar9 = PTR_LAB_00036774 + 0x6414;
LAB_0001ee74:
      (*(code *)PTR_lib2sp_set_error_0003683c)(param_1,0xb,puVar6,puVar9);
      return;
    }
    iVar12 = param_1 + 0x568;
    (*(code *)PTR_lib2sp_close_dpi_sig_000368d4)(param_1,param_1 + 0x538,iVar12,iVar2 + 0x11c);
    if (*(int *)(param_1 + 8) != 0) {
      return;
    }
    if (*(int *)(param_1 + 0x608) != 0) {
      return;
    }
    (*(code *)PTR_lib2sp_save_dpi_sig_hash_00036834)(param_1,iVar12);
    if (*(int *)(param_1 + 8) != 0) {
      return;
    }
    if (*(int *)(param_1 + 0x608) != 0) {
      return;
    }
    (*(code *)PTR_lib2sp_save_dpi_filename_00036790)(param_1,iVar12);
    iVar2 = *(int *)(param_1 + 8);
  }
  else {
    if (uVar4 < uVar15) {
      return;
    }
    if ((uVar4 == uVar15) && (*(uint *)(param_1 + 0x514) < uVar14)) {
      return;
    }
    if (uVar3 == 0x26) {
      (*(code *)PTR_lib2sp_close_script_00036894)
                (param_1,param_1 + 0x560,auStack_10b8,local_10c4,local_10c8);
      iVar2 = *(int *)(param_1 + 8);
    }
    else {
      if (uVar3 < 0x27) {
        if ((uVar3 != 1) && (uVar3 != 3)) goto LAB_0001ef54;
      }
      else if (uVar3 != 0x2f) {
        if (uVar3 != 1000) goto LAB_0001ef54;
        iVar2 = *(int *)(param_1 + 0x574);
        goto LAB_0001ee54;
      }
      (*(code *)PTR_lib2sp_close_file_00036914)(param_1,param_1 + 0x538,auStack_10b8,local_10bc);
      iVar2 = *(int *)(param_1 + 8);
    }
  }
  if (iVar2 != 0) {
    return;
  }
  if (*(int *)(param_1 + 0x608) != 0) {
    return;
  }
LAB_0001ef54:
  *(undefined4 *)(param_1 + 0x52c) = 0;
  *(undefined4 *)(param_1 + 0x528) = 0;
  *(undefined1 *)(param_1 + 0x530) = 0;
  *param_7 = 1;
  return;
}



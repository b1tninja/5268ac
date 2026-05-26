
uint pkg_stream_handler(int param_1,undefined4 param_2,undefined4 param_3,int param_4,
                       undefined4 param_5,int *param_6)

{
  bool bVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  uint *puVar6;
  undefined1 uVar10;
  int iVar7;
  int *piVar8;
  int iVar9;
  int iVar11;
  undefined *puVar12;
  undefined4 uVar13;
  uint uVar14;
  uint uVar15;
  int iVar16;
  code *pcVar17;
  undefined8 uVar18;
  char acStack_4b0 [4];
  int iStack_4ac;
  int iStack_4a8;
  int iStack_4a4;
  int iStack_4a0;
  uint uStack_49c;
  undefined1 auStack_498 [4];
  undefined4 uStack_494;
  int iStack_490;
  int iStack_48c;
  int iStack_488;
  int aiStack_484 [3];
  undefined1 auStack_478 [8];
  int iStack_470;
  uint uStack_46c;
  int aiStack_468 [3];
  undefined1 auStack_45c [36];
  int iStack_438;
  undefined2 uStack_434;
  short sStack_432;
  undefined1 auStack_430 [32];
  int aiStack_410 [17];
  undefined1 auStack_3cc [268];
  undefined4 uStack_2c0;
  undefined1 *puStack_2bc;
  int iStack_2b8;
  int iStack_2b4;
  int iStack_2b0;
  int iStack_2ac;
  uint uStack_2a8;
  uint uStack_2a4;
  int iStack_2a0;
  undefined4 uStack_29c;
  undefined4 auStack_298 [2];
  int iStack_290;
  uint uStack_28c;
  int iStack_288;
  uint uStack_284;
  int iStack_280;
  uint uStack_27c;
  int iStack_278;
  uint uStack_274;
  int iStack_270;
  int iStack_26c;
  uint uStack_268;
  int iStack_264;
  int iStack_260;
  int iStack_25c;
  undefined4 uStack_258;
  int iStack_254;
  undefined4 uStack_23c;
  char cStack_230;
  char cStack_22f;
  char cStack_22e;
  char cStack_22d;
  undefined1 auStack_228 [24];
  undefined1 auStack_210 [12];
  int iStack_204;
  int iStack_200;
  int iStack_1fc;
  int iStack_1f8;
  uint uStack_1f4;
  int iStack_1e8;
  uint uStack_1e4;
  int iStack_1e0;
  uint uStack_1dc;
  char cStack_1c8;
  uint uStack_1c4;
  undefined1 uStack_1c0;
  char cStack_1bf;
  undefined1 *puStack_1bc;
  undefined4 uStack_1b8;
  undefined1 auStack_1b0 [352];
  undefined4 uStack_50;
  int iStack_4c;
  int iStack_48;
  uint uStack_44;
  int iStack_40;
  undefined4 uStack_3c;
  int iStack_38;
  undefined8 uStack_34;
  uint uStack_2c;
  
  uStack_2c = *(uint *)(param_1 + 0x1d8);
  iStack_488 = 0;
  uStack_34._4_4_ = (*(code *)PTR_getppid_00447410)();
  uVar3 = (*(code *)PTR_getpid_004477a4)();
  pkg_log_trace(uStack_2c,&UNK_00434a0c,__FUNCTION___24622,uStack_34._4_4_,uVar3,param_5);
  (*(code *)PTR_memset_0044771c)(&uStack_2c0,0,0x110);
  puVar12 = PTR_malloc_004475f4;
  uStack_44 = *(uint *)(param_1 + 0xec);
  iStack_48 = *(int *)(param_1 + 0xe8);
  *param_6 = 0;
  iStack_270 = -1;
  iStack_26c = -1;
  iVar4 = (*(code *)puVar12)(16000);
  if (iVar4 == 0) {
    (*(code *)PTR_syslog_004477f0)(3,&UNK_00434a34);
    return 0xc;
  }
  pkg_status_init(auStack_1b0);
  pkg_status_set_pkg(auStack_1b0,param_4);
  pkg_status_inherit_rates(param_3,auStack_1b0);
  pkg_status_disable(auStack_1b0);
  pkg_status_report(param_1,param_2,auStack_1b0);
  uStack_2a8 = 16000;
  auStack_298[0] = 0xffffffff;
  iStack_2b4 = 0;
  uStack_29c = 1;
  uStack_2c0 = param_3;
  puStack_2bc = auStack_1b0;
  iStack_2b0 = param_4;
  iStack_2ac = iVar4;
  iStack_264 = (*(code *)PTR_tu_uptime_secs_00447620)();
  uVar5 = pkg_util_http_init(&uStack_258,param_5);
  puVar12 = PTR_nu_uri_index_00447408;
  if (uVar5 != 0) {
    puVar12 = &UNK_00434a50;
    uVar14 = uVar5;
    goto code_r0x00424198;
  }
  if (*(int *)(param_1 + 0xdc) == 0) {
    *(undefined4 **)(param_1 + 0xdc) = &uStack_258;
    uVar14 = (*(code *)puVar12)(aiStack_410,param_5);
    if (uVar14 != 0) {
      (*(code *)PTR_snprintf_004477b0)(iVar4,16000,&UNK_00434a84);
      goto code_r0x004221bc;
    }
    iStack_25c = aiStack_410[0];
    iVar9 = (*(code *)PTR_pipe_00447538)(&iStack_270);
    if (iVar9 == 0) {
      uVar5 = pkg_util_set_nonblock(iStack_270);
      uVar14 = pkg_util_set_nonblock(iStack_26c);
      uVar14 = uVar14 | uVar5;
      if (uVar14 != 0) {
        uVar5 = (*(code *)PTR_strerror_00447428)(uVar14);
        puVar12 = &UNK_00434ab4;
        goto code_r0x00424198;
      }
      uVar14 = pkg_update_httpc_create(param_1,&uStack_2c0);
      bVar1 = false;
      if (uVar14 == 0) {
        uVar14 = (*(code *)PTR_lib2sp_create_context_004477a0)(&iStack_2b8);
        if (uVar14 != 0) {
          uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
          puVar12 = &UNK_00434ad8;
code_r0x00422498:
          bVar1 = false;
          (*(code *)PTR_snprintf_004477b0)(iVar4,16000,puVar12,uVar3);
          goto code_r0x0042441c;
        }
        uVar14 = (*(code *)PTR__cm_tran_begin_004476f0)(param_2,1,&uStack_494,&UNK_00434490,0x683);
        if (uVar14 != 0) {
          uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
          (*(code *)PTR_syslog_004477f0)(3,&UNK_00434afc,uVar3);
          bVar1 = false;
          goto code_r0x0042441c;
        }
        uVar14 = pkg_util_set_2sp_sys_info(param_1,uStack_494,iStack_2b8);
        if (uVar14 != 0) {
          uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
          (*(code *)PTR_snprintf_004477b0)(iVar4,16000,&UNK_00434b34,uVar3);
          (*(code *)PTR__cm_tran_abort_0044752c)(uStack_494,&UNK_00434490,0x68c);
          goto code_r0x004221bc;
        }
        uVar10 = (*(code *)PTR_tw_ulib_is_trustengcert_enabled_00447650)(uStack_494);
        puVar12 = PTR__cm_tran_commit_004477d0;
        *(undefined1 *)(param_4 + 0x98c) = uVar10;
        (*(code *)puVar12)(uStack_494,&UNK_00434490,0x691);
        uVar14 = (*(code *)PTR_lib2sp_set_log_facility_00447564)(iStack_2b8,0xffffffff);
        if (uVar14 != 0) {
          uVar5 = (*(code *)PTR_strerror_00447428)(uVar14);
          puVar12 = &UNK_00434b64;
          goto code_r0x00424198;
        }
        if ((*(uint *)(param_1 + 4) & 0x408000) == 0x400000) {
          uVar14 = pkg_cert_vfy_init(param_1,param_2,iVar4,16000,auStack_3cc,&iStack_488,
                                     iStack_25c == 5);
          bVar1 = false;
          if (uVar14 != 0) goto code_r0x0042441c;
          uVar14 = (*(code *)PTR_lib2sp_enable_verify_004476a8)(iStack_2b8,iStack_488);
          if (uVar14 != 0) {
            uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
            puVar12 = &UNK_00434b88;
            goto code_r0x00422498;
          }
        }
        else {
          uVar14 = (*(code *)PTR_lib2sp_disable_verify_004475a0)(iStack_2b8);
          if (uVar14 != 0) {
            uVar5 = (*(code *)PTR_strerror_00447428)(uVar14);
            puVar12 = &UNK_00434ba8;
            goto code_r0x00424198;
          }
        }
        iVar7 = pkg_log_getlogpath(*(undefined4 *)(param_1 + 0x1d8));
        iVar9 = iStack_2b8;
        if (iVar7 != 0) {
          uVar3 = pkg_log_getlogpath(*(undefined4 *)(param_1 + 0x1d8));
          uVar14 = (*(code *)PTR_lib2sp_set_log_file_00447938)(iVar9,uVar3);
          if (uVar14 == 0) goto code_r0x0042255c;
          uVar13 = *(undefined4 *)(param_1 + 0x1d8);
          uVar3 = pkg_log_getlogpath(uVar13);
          pkg_log_error(uVar13,&UNK_00434bcc,uVar3);
code_r0x00422630:
          uVar5 = (*(code *)PTR_strerror_00447428)(uVar14);
          puVar12 = &UNK_00434d5c;
          goto code_r0x00424198;
        }
code_r0x0042255c:
        uVar14 = (*(code *)PTR_lib2sp_set_max_tlv_size_004477e0)(iStack_2b8,0x20000);
        if (uVar14 != 0) {
          uVar3 = *(undefined4 *)(param_1 + 0x1d8);
          puVar12 = &UNK_00434c0c;
code_r0x00422620:
          pkg_log_error(uVar3,puVar12);
          goto code_r0x00422630;
        }
        uVar14 = (*(code *)PTR_lib2sp_set_max_signature_size_00447730)(iStack_2b8,0x40000);
        if (uVar14 != 0) {
          uVar3 = *(undefined4 *)(param_1 + 0x1d8);
          puVar12 = &UNK_00434c44;
          goto code_r0x00422620;
        }
        uVar14 = (*(code *)PTR_lib2sp_disallow_compression_0044754c)(iStack_2b8);
        if (uVar14 != 0) {
          uVar3 = *(undefined4 *)(param_1 + 0x1d8);
          puVar12 = &UNK_00434c80;
          goto code_r0x00422620;
        }
        iStack_4c = param_1 + 0x110;
        pkg_config_getfsspacelimit(iStack_4c);
        uVar14 = (*(code *)PTR_lib2sp_enable_space_monitor_004476b8)(iStack_2b8);
        if (uVar14 != 0) {
          uVar3 = *(undefined4 *)(param_1 + 0x1d8);
          puVar12 = &UNK_00434cbc;
          goto code_r0x00422620;
        }
        iVar9 = (*(code *)PTR_lib2sp_set_stream_url_004474bc)(iStack_2b8,param_5);
        if (iVar9 != 0) {
          pkg_log_error(*(undefined4 *)(param_1 + 0x1d8),&UNK_00434cf8,iVar9);
        }
        uVar14 = (*(code *)PTR_dpi_util_check_filetype_004475fc)
                           (*(undefined4 *)(param_4 + 0x2c),param_4 + 0x70,param_5,
                            *(undefined1 *)(param_4 + 0x98c));
        if (uVar14 == 0) {
          iVar9 = (*(code *)PTR_dpi_util_is_filetype_dpi_004476ac)(*(undefined4 *)(param_4 + 0x2c));
          if (iVar9 != 0) {
            (*(code *)PTR_lib2sp_set_dpi_sig_data_0044759c)(iStack_2b8,param_4 + 0x70);
          }
          pkg_status_set_active(auStack_1b0,*(undefined4 *)(param_4 + 0x6c));
          pkg_status_set_active(param_3,*(undefined4 *)(param_4 + 0x6c));
          iStack_260 = (*(code *)PTR_tu_uptime_secs_00447620)();
          iStack_40 = iVar4;
          iStack_38 = param_4;
code_r0x004240f0:
          if (cStack_22f == '\0') {
            iVar4 = (*(code *)PTR_tu_uptime_secs_00447620)();
            uVar14 = pkg_check_timeout(param_1,&uStack_2c0,iVar4);
            if (uVar14 != 0) {
              uVar3 = *(undefined4 *)(param_1 + 0x1d8);
              puVar12 = &UNK_00434d7c;
              pcVar17 = (code *)PTR_pkg_log_warning_004471f4;
code_r0x00422ba0:
              (*pcVar17)(uVar3,puVar12,uVar14);
code_r0x00423df4:
              pkg_log_warning(*(undefined4 *)(param_1 + 0x1d8),&UNK_00435654,__FUNCTION___24622,
                              uVar14);
              (*(code *)PTR_dpi_util_update_fail_00447468)(*(undefined4 *)(iStack_38 + 0x2c),uVar14)
              ;
              if (uVar14 == 4) {
                uVar5 = uStack_284 + uStack_28c;
                iVar4 = (uint)(uVar5 < uStack_284) + iStack_288 + iStack_290;
                pkg_log_warning(*(undefined4 *)(param_1 + 0x1d8),&UNK_00435674,__FUNCTION___24622);
                if ((iStack_278 < iVar4) || ((iStack_278 == iVar4 && (uStack_274 < uVar5))))
                goto code_r0x004246e4;
                cStack_22f = '\x01';
                goto code_r0x00424100;
              }
code_r0x004246e4:
              iVar9 = iStack_4c;
              if (uVar14 != 0) {
code_r0x004240c8:
                do {
                  do {
                    do {
                      iVar4 = iStack_40;
                      if (cStack_22d == '\0') goto code_r0x004221bc;
                      iVar7 = pkg_restart_ok(param_1,&uStack_2c0);
                      iVar4 = iStack_40;
                      if (iVar7 == 0) goto code_r0x004221bc;
                      cStack_22d = '\0';
                      uVar5 = pkg_config_getreconmaxbackoff(iVar9);
                      iVar4 = pkg_config_getrecontimer(iVar9);
                      if (uVar5 < uStack_268) {
                        uStack_268 = uVar5;
                      }
                      iVar7 = 0;
                      if (0 < (int)uStack_268) {
                        iVar7 = iVar4 << (uStack_268 - 1 & 0x1f);
                      }
                      iVar4 = (*(code *)PTR_tu_uptime_secs_00447620)();
                      uVar14 = pkg_get_timeout_isra_2(param_1,&uStack_2c0,&iStack_4a8);
                    } while ((uVar14 != 0) ||
                            (uVar14 = 0x91, (uint)(iStack_264 + iStack_4a8) <= (uint)(iVar7 + iVar4)
                            ));
                    (*(code *)PTR_syslog_004477f0)(4,&UNK_004356c4,iStack_2ac,iVar7);
                    (*(code *)PTR_sleep_004477d4)(iVar7);
                    pkg_util_http_cleanup(&uStack_258);
                    uVar14 = pkg_util_http_init(&uStack_258,param_5);
                  } while (uVar14 != 0);
                  uStack_268 = uStack_268 + 1;
                  cStack_230 = '\0';
                  uVar14 = pkg_update_httpc_create(param_1,&uStack_2c0);
                } while (uVar14 != 0);
                (*(code *)PTR_syslog_004477f0)(4,&UNK_004356ec);
                cStack_22d = '\0';
              }
              goto code_r0x004240f0;
            }
            iVar9 = iVar4 - iStack_260;
            if ((iStack_2a0 <= iVar9) && (cStack_230 != '\0')) {
              iVar7 = pkg_restart_ok(param_1,&uStack_2c0);
              if (iVar7 == 0) {
                iStack_2a0 = 0x3c;
                iStack_260 = iVar4;
              }
              iStack_2a0 = pkg_config_getactivitytimeout(iStack_4c);
              if (iVar9 < iStack_2a0) goto code_r0x0042280c;
              (*(code *)PTR_snprintf_004477b0)(iStack_2ac,uStack_2a8,&UNK_004349e0,iStack_2a0);
              cStack_22d = '\x01';
              pkg_log_warning(*(undefined4 *)(param_1 + 0x1d8),&UNK_00434da8,0x91);
              uVar14 = 0x91;
              goto code_r0x00423df4;
            }
code_r0x0042280c:
            iVar4 = iStack_2ac;
            if ((iStack_2b4 == 0) || (uStack_1c4 == 0)) {
              iStack_438 = iStack_270;
              uStack_434 = 1;
              iStack_4a0 = 4;
              uVar14 = (*(code *)PTR_httpc_poll_setup_004475d4)
                                 (uStack_258,auStack_430,&iStack_4a0,auStack_498);
              if (uVar14 == 0) {
                iVar4 = (*(code *)PTR_poll_004477d8)(&iStack_438,iStack_4a0 + 1,1000);
                if (iVar4 < 0) {
                  piVar8 = (int *)(*(code *)PTR___errno_location_004476c0)();
                  iVar4 = *piVar8;
                  pkg_log_info(*(undefined4 *)(param_1 + 0x1d8),&UNK_00434e50,iVar4);
                  if (iVar4 != 4) {
                    (*(code *)PTR_sleep_004477d4)(1);
                  }
                  goto code_r0x00423ec4;
                }
                iVar4 = (int)sStack_432;
                while (uVar3 = uStack_23c, iVar4 != 0) {
                  iVar4 = (*(code *)PTR_read_00447708)(iStack_270,iStack_2ac,uStack_2a8);
                }
                uVar14 = (*(code *)PTR_httpc_poll_dispatch_00447788)
                                   (uStack_258,auStack_430,iStack_4a0);
                if (uVar14 == 0) {
                  pkg_log_debug(*(undefined4 *)(param_1 + 0x1d8),&UNK_00434ebc,uVar3);
                  uStack_50 = uVar3;
code_r0x00423de0:
                  do {
                    if (cStack_22f != '\0') goto code_r0x00423ec4;
                    aiStack_468[0] = iStack_254;
                    aiStack_468[1] = 2;
                    uVar14 = (*(code *)PTR_httpc_req_poll_004477ac)(uStack_258,aiStack_468,1);
                    uVar3 = uStack_50;
                    if (uVar14 != 0) {
                      pkg_log_warning(*(undefined4 *)(param_1 + 0x1d8),&UNK_00434ed4,uVar14);
                      puVar12 = &UNK_00434efc;
                      goto code_r0x00422a90;
                    }
                    if ((aiStack_468[2] & 0xcU) != 0) {
                      pkg_log_debug(*(undefined4 *)(param_1 + 0x1d8),&UNK_00434f1c);
                      (*(code *)PTR_snprintf_004477b0)
                                (iStack_2ac,uStack_2a8,&UNK_00434f50,uVar3,0xca);
code_r0x00422d48:
                      cStack_22d = '\x01';
                      uVar14 = 0xca;
                      goto code_r0x00423df4;
                    }
                    if ((aiStack_468[2] & 2U) == 0) {
                      pkg_log_debug(*(undefined4 *)(param_1 + 0x1d8),&UNK_00434f70);
                      goto code_r0x00423ec4;
                    }
                    uStack_49c = uStack_2a8;
                    uVar14 = (*(code *)PTR_httpc_req_read_0044753c)
                                       (uStack_258,iStack_254,iStack_2ac,&uStack_49c);
                    if (uVar14 == 0) {
                      if (cStack_230 == '\0') {
                        uVar14 = pkg_util_httpc_connected
                                           (param_1,iStack_2ac,uStack_2a8,&uStack_258,acStack_4b0);
                        if (uVar14 != 0) {
code_r0x00422c34:
                          cStack_22d = '\x01';
                          pkg_log_info(*(undefined4 *)(param_1 + 0x1d8),&UNK_00434ff4,
                                       __FUNCTION___24583,uVar14);
                          goto code_r0x00423df4;
                        }
                        if (acStack_4b0[0] == '\0') {
                          cStack_230 = '\x01';
                        }
                        else {
                          if (-1 < iStack_254) {
                            (*(code *)PTR_httpc_req_free_004477c0)(uStack_258);
                          }
                          iStack_254 = -1;
                          uVar14 = pkg_util_httpc_req_create
                                             (param_1,iStack_2ac,uStack_2a8,&uStack_258);
                          if (uVar14 != 0) goto code_r0x00422c34;
                        }
                        if (cStack_230 == '\0') {
                          pkg_log_debug(*(undefined4 *)(param_1 + 0x1d8),&UNK_00435020);
                          goto code_r0x00423ec4;
                        }
                        uStack_50 = uStack_23c;
                      }
                      pkg_status_update(param_1,param_2,puStack_2bc,
                                        *(undefined4 *)(iStack_2b0 + 0x6c),0,uStack_49c);
                      uVar5 = 0;
                      pkg_status_update(param_1,param_2,uStack_2c0,
                                        *(undefined4 *)(iStack_2b0 + 0x6c),0,uStack_49c);
                      if (uStack_49c == 0) {
                        if (((iStack_2b4 == 0) || (iStack_280 < iStack_290)) ||
                           ((iStack_290 == iStack_280 && (uStack_27c < uStack_28c)))) {
                          (*(code *)PTR_snprintf_004477b0)
                                    (iStack_2ac,uStack_2a8,&UNK_00435048,uStack_50);
                          goto code_r0x00422d48;
                        }
                        uVar14 = (*(code *)PTR_pthread_mutex_lock_00447690)(auStack_228);
                        if (uVar14 != 0) {
                          pkg_log_debug(*(undefined4 *)(param_1 + 0x1d8),&UNK_00435068,uVar14);
                          (*(code *)PTR_snprintf_004477b0)
                                    (iStack_2ac,uStack_2a8,&UNK_00435094,uVar14);
                          goto code_r0x00423df4;
                        }
                        uStack_1c0 = 1;
                        (*(code *)PTR_pthread_cond_broadcast_00447830)(auStack_210);
                        (*(code *)PTR_pthread_mutex_unlock_00447764)(auStack_228);
                        cStack_22f = '\x01';
                        goto code_r0x00423ec4;
                      }
                      iStack_260 = (*(code *)PTR_tu_uptime_secs_00447620)();
                      uStack_274 = uStack_49c + uStack_274;
                      iStack_278 = (uint)(uStack_274 < uStack_49c) + iStack_278;
                      pkg_log_trace(*(undefined4 *)(param_1 + 0x1d8),&UNK_004350a8);
                      iVar4 = iStack_2ac;
                      uVar2 = uStack_49c;
                      uStack_268 = 0;
                      uStack_3c = uStack_23c;
                      if (iStack_2b4 != 0) {
                        uVar14 = (*(code *)PTR_lib2sp_check_data_004474f0)
                                           (iStack_2b8,iStack_2ac,uStack_49c);
                        if (uVar14 != 0) {
                          uVar5 = uVar14;
                          (*(code *)PTR_snprintf_004477b0)
                                    (iStack_2ac,uStack_2a8,&UNK_004350d0,uStack_3c,uVar14);
                          uVar3 = *(undefined4 *)(param_1 + 0x1d8);
                          puVar12 = &UNK_004350f4;
code_r0x00423d88:
                          pkg_log_error(uVar3,puVar12,__FUNCTION___24529,uVar14,uVar5);
code_r0x00423da0:
                          pkg_log_warning(*(undefined4 *)(param_1 + 0x1d8),&UNK_0043562c,uVar14);
                          cStack_22d = '\0';
                          goto code_r0x00423df4;
                        }
                      }
                      iVar9 = 0;
                      while ((iVar7 = iStack_2b0, iVar9 < (int)uVar2 && (cStack_22f == '\0'))) {
                        uVar15 = uVar2 - iVar9;
                        if (iStack_2b4 == 0) {
                          if (0 < (int)uVar15) {
                            pkg_status_set_active(puStack_2bc,uStack_29c);
                            pkg_status_set_active(uStack_2c0,uStack_29c);
                            uVar14 = (*(code *)PTR_lib2sp_install_data_0044785c)
                                               (iStack_2b8,iVar4 + iVar9,uVar15,&iStack_4a8);
                            if (uVar14 == 0) {
                              pkg_status_update(param_1,param_2,puStack_2bc,uStack_29c,
                                                iStack_4a8 >> 0x1f,iStack_4a8);
                              uVar5 = iStack_4a8 >> 0x1f;
                              pkg_status_update(param_1,param_2,uStack_2c0,uStack_29c,uVar5,
                                                iStack_4a8);
                              pkg_status_set_inactive(puStack_2bc,uStack_29c);
                              pkg_status_set_inactive(uStack_2c0,uStack_29c);
                              iVar16 = iStack_4a8;
                              iStack_288 = (uint)(uStack_284 + iStack_4a8 < uStack_284) +
                                           iStack_288 + (iStack_4a8 >> 0x1f);
                              uStack_284 = uStack_284 + iStack_4a8;
                              uVar14 = (*(code *)PTR_lib2sp_get_state_004478ac)
                                                 (iStack_2b8,&iStack_4ac);
                              iVar11 = iStack_2ac;
                              if (uVar14 != 0) {
                                uStack_2c = uStack_2a8;
                                uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                (*(code *)PTR_snprintf_004477b0)
                                          (iVar11,uStack_2c,&UNK_00435188,uVar3);
                                uVar3 = *(undefined4 *)(param_1 + 0x1d8);
                                puVar12 = &UNK_004351a4;
                                goto code_r0x004233d8;
                              }
                              if (2 < iStack_4ac - 3U) {
                                pkg_log_info(*(undefined4 *)(param_1 + 0x1d8),&UNK_004351c4,
                                             __FUNCTION___24498);
                                goto code_r0x00424714;
                              }
                              if ((*(uint *)(iVar7 + 0x44) & 0x400) == 0) {
code_r0x00423100:
                                uVar14 = (*(code *)PTR_lib2sp_get_payload_size_00447850)
                                                   (iStack_2b8,&iStack_290);
                                iVar11 = iStack_2ac;
                                if (uVar14 == 0) {
                                  iVar11 = *(int *)(iVar7 + 0x54);
                                  uVar5 = uStack_284 + uStack_28c;
                                  if (iVar11 < 0) {
                                    uStack_46c = uVar5 - 0x1000000;
                                    iStack_470 = (uint)(uStack_46c < uVar5) +
                                                 (uint)(uVar5 < uStack_284) +
                                                 iStack_288 + iStack_290 + -1;
                                  }
                                  else {
                                    uStack_46c = uVar5 - iVar11;
                                    iStack_470 = (((uint)(uVar5 < uStack_284) +
                                                  iStack_288 + iStack_290) - (iVar11 >> 0x1f)) -
                                                 (uint)(uVar5 < uStack_46c);
                                  }
                                  pkg_status_add_work(uStack_2c0,uStack_29c,iStack_470,uStack_46c);
                                  pkg_status_add_work(uStack_2c0,*(undefined4 *)(iVar7 + 0x6c),
                                                      iStack_470,uStack_46c);
                                  iVar11 = (*(code *)PTR_lib2sp_get_verify_status_004478f8)
                                                     (iStack_2b8,&iStack_470,auStack_478);
                                  if (iVar11 == 0) {
                                    pkg_status_add_work(puStack_2bc,4,iStack_470,uStack_46c);
                                    pkg_status_add_work(uStack_2c0,4,iStack_470,uStack_46c);
                                  }
                                  else {
                                    pkg_log_info(*(undefined4 *)(param_1 + 0x1d8),&UNK_00435264,
                                                 __FUNCTION___24498,iVar11);
                                  }
                                  uStack_46c = uStack_284 + uStack_28c;
                                  iStack_470 = (uint)(uStack_46c < uStack_284) +
                                               iStack_288 + iStack_290;
                                  pkg_status_add_work(puStack_2bc,uStack_29c);
                                  pkg_status_add_work(puStack_2bc,*(undefined4 *)(iVar7 + 0x6c),
                                                      iStack_470,uStack_46c);
                                  pkg_status_enable(puStack_2bc);
                                  pkg_status_report(param_1,param_2,puStack_2bc);
                                  iVar7 = (*(code *)PTR_lib2sp_get_buffer_hint_004473d4)
                                                    (iStack_2b8,&iStack_4a4);
                                  if (iVar7 != 0) {
                                    iStack_4a4 = -1;
                                    pkg_log_info(*(undefined4 *)(param_1 + 0x1d8),&UNK_00435294,
                                                 __FUNCTION___24498,uStack_28c,iStack_290,uStack_28c
                                                 ,iVar7);
                                  }
                                  uVar5 = iStack_4a4 >> 0x1f;
                                  uVar14 = pkg_spool_init(param_1,param_2,iStack_290,uStack_28c,
                                                          uVar5,iStack_4a4,auStack_228,auStack_298);
                                  iVar7 = iStack_2ac;
                                  if (uVar14 == 0) {
                                    iStack_204 = iStack_26c;
                                    puStack_1bc = puStack_2bc;
                                    uStack_1b8 = uStack_2c0;
                                    uVar14 = (*(code *)PTR_pthread_attr_init_0044772c)(auStack_45c);
                                    if (uVar14 == 0) {
                                      uVar14 = (*(code *)PTR_pthread_attr_setdetachstate_00447674)
                                                         (auStack_45c,1);
                                      if (uVar14 == 0) {
                                        uVar14 = (*(code *)PTR_pthread_attr_setstacksize_0044767c)
                                                           (auStack_45c,32000);
                                        uVar15 = *(uint *)(param_1 + 0x1d8);
                                        if (uVar14 == 0) {
                                          cStack_1bf = '\x01';
                                          iStack_200 = iStack_2b8;
                                          iStack_1fc = param_1;
                                          uStack_2c = uVar15;
                                          uVar3 = (*(code *)PTR_getppid_00447410)();
                                          uStack_34._0_4_ = uVar3;
                                          uVar3 = (*(code *)PTR_getpid_004477a4)();
                                          pkg_log_trace(uStack_2c,&UNK_00435418,uStack_34._0_4_,
                                                        uVar3);
                                          uVar14 = (*(code *)PTR_pthread_create_0044787c)
                                                             (&iStack_2b4,auStack_45c,
                                                              pkgman_run_installer,auStack_228);
                                          if (uVar14 == 0) {
                                            (*(code *)PTR_pthread_attr_destroy_004473e0)
                                                      (auStack_45c);
                                            pkg_log_trace(*(undefined4 *)(param_1 + 0x1d8),
                                                          &UNK_004354b4,32000);
                                            goto code_r0x00424714;
                                          }
                                          uVar13 = *(undefined4 *)(param_1 + 0x1d8);
                                          uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                          pkg_log_error(uVar13,&UNK_0043545c,uVar3);
                                          iVar4 = iStack_2ac;
                                          uStack_2c = uStack_2a8;
                                          uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                          puVar12 = &UNK_00435494;
                                        }
                                        else {
                                          uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                          pkg_log_error(uVar15,&UNK_004353d8,32000,uVar3);
                                          iVar4 = iStack_2ac;
                                          uStack_2c = uStack_2a8;
                                          uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                          puVar12 = &UNK_0043268c;
                                        }
                                      }
                                      else {
                                        uVar13 = *(undefined4 *)(param_1 + 0x1d8);
                                        uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                        pkg_log_error(uVar13,&UNK_00435358,uVar3);
                                        iVar4 = iStack_2ac;
                                        uStack_2c = uStack_2a8;
                                        uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                        puVar12 = &UNK_004353b0;
                                      }
                                      (*(code *)PTR_snprintf_004477b0)
                                                (iVar4,uStack_2c,puVar12,uVar3);
                                      (*(code *)PTR_pthread_attr_destroy_004473e0)(auStack_45c);
                                      cStack_1bf = '\0';
                                      iStack_200 = 0;
                                      (*(code *)PTR_close_00447498)(auStack_298[0]);
                                      auStack_298[0] = 0xffffffff;
                                      pkg_spool_cleanup(param_1,auStack_228);
                                    }
                                    else {
                                      uVar13 = *(undefined4 *)(param_1 + 0x1d8);
                                      uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                      pkg_log_error(uVar13,&UNK_00435318,uVar3);
                                      iVar4 = iStack_2ac;
                                      uStack_2c = uStack_2a8;
                                      uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                      (*(code *)PTR_snprintf_004477b0)
                                                (iVar4,uStack_2c,&UNK_004325d8,uVar3);
                                    }
                                    goto code_r0x004236f8;
                                  }
                                  uStack_2c = uStack_2a8;
                                  uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                  (*(code *)PTR_snprintf_004477b0)
                                            (iVar7,uStack_2c,&UNK_004352d4,uVar3);
                                  uVar3 = *(undefined4 *)(param_1 + 0x1d8);
                                  puVar12 = &UNK_004352f4;
                                }
                                else {
                                  uStack_2c = uStack_2a8;
                                  uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                  (*(code *)PTR_snprintf_004477b0)
                                            (iVar11,uStack_2c,&UNK_00435218,uVar3);
                                  uVar3 = *(undefined4 *)(param_1 + 0x1d8);
                                  puVar12 = &UNK_0043523c;
                                }
                                goto code_r0x004233d8;
                              }
                              uVar14 = pkg_stream_resolve_pkg(param_1,param_2,&uStack_2c0);
                              if (uVar14 == 0) goto code_r0x00423100;
                              uVar5 = uVar14;
                              pkg_log_error(*(undefined4 *)(param_1 + 0x1d8),&UNK_004351e4,
                                            __FUNCTION___24498,*(undefined4 *)(iVar7 + 0x44),uVar14)
                              ;
                            }
                            else {
                              uVar5 = uVar14;
                              (*(code *)PTR_snprintf_004477b0)
                                        (iStack_2ac,uStack_2a8,&UNK_00435140,uStack_23c,uVar14);
                              uVar3 = *(undefined4 *)(param_1 + 0x1d8);
                              puVar12 = &UNK_00435164;
code_r0x004233d8:
                              pkg_log_error(uVar3,puVar12,__FUNCTION___24498,uVar14);
                            }
code_r0x004236f8:
                            uVar3 = *(undefined4 *)(param_1 + 0x1d8);
                            puVar12 = &UNK_004354f8;
                            goto code_r0x00423d88;
                          }
                          pkg_log_info(*(undefined4 *)(param_1 + 0x1d8),&UNK_00435124,
                                       __FUNCTION___24498,uVar15);
                          iVar16 = 0;
code_r0x00424714:
                          iVar9 = iVar9 + iVar16;
                          if ((iStack_2b4 != 0) && (iVar9 < (int)uVar2)) {
                            uVar14 = (*(code *)PTR_lib2sp_check_data_004474f0)
                                               (iStack_2b8,iVar4 + iVar9,uVar2 - iVar9);
                            if (uVar14 != 0) {
                              (*(code *)PTR_snprintf_004477b0)
                                        (iStack_2ac,uStack_2a8,&UNK_00435520,uStack_3c,uVar14);
                              pkg_log_error(*(undefined4 *)(param_1 + 0x1d8),&UNK_0043554c,
                                            __FUNCTION___24529,uStack_3c,uVar2,uVar14);
                              goto code_r0x00423da0;
                            }
                          }
                          uVar14 = pkg_config_getpayloadtimeout(iStack_4c);
                          if (uStack_2a4 < uVar14) {
                            uStack_2a4 = uVar14;
                          }
                        }
                        else {
                          if (0 < (int)uVar15) {
                            uVar14 = 0;
                            if ((*(uint *)(param_1 + 4) & 0x4000) == 0) {
code_r0x0042384c:
                              uStack_2c = uVar14;
                              uVar18 = pkg_config_gettmpspacelimit(iStack_4c);
                              uStack_34 = uVar18;
                              uVar14 = (*(code *)PTR_pthread_mutex_lock_00447690)(auStack_228);
                              if (uVar14 != 0) {
code_r0x00423c48:
                                iVar7 = iStack_2ac;
                                uStack_2c = uStack_2a8;
                                uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                puVar12 = &UNK_00433fa4;
                                goto code_r0x00423c74;
                              }
                              uVar18 = uStack_34;
                              if (uStack_2c != 0) {
                                uVar5 = uStack_34._0_4_;
                                uVar14 = pkg_spool_resize(param_1,uStack_2c,
                                                          (iStack_290 - iStack_280) -
                                                          (uint)(uStack_28c <
                                                                uStack_28c - uStack_27c),
                                                          uStack_28c - uStack_27c,uStack_34,
                                                          auStack_228,auStack_298[0]);
                                uVar18 = uStack_34;
                                if (uVar14 != 0) {
                                  (*(code *)PTR_pthread_mutex_unlock_00447764)(auStack_228);
                                  iVar7 = iStack_2ac;
                                  uStack_2c = uStack_2a8;
                                  uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                  puVar12 = &UNK_004355b4;
                                  goto code_r0x00423c74;
                                }
                              }
                              uStack_34._0_4_ = uStack_1dc - uStack_1e4;
                              iVar7 = (iStack_1e0 - iStack_1e8) -
                                      (uint)(uStack_1dc < uStack_34._0_4_);
                              if ((iVar7 < 1) &&
                                 (((iVar7 != 0 || (uStack_34._0_4_ == 0)) && (cStack_1bf != '\0'))))
                              {
                                uStack_34 = uVar18;
                                pkg_status_set_inactive
                                          (puStack_2bc,*(undefined4 *)(iStack_2b0 + 0x6c));
                                pkg_status_set_inactive
                                          (uStack_2c0,*(undefined4 *)(iStack_2b0 + 0x6c));
                                uVar18 = uStack_34;
                                while( true ) {
                                  uStack_34._4_4_ = (uint)uVar18;
                                  uStack_34._0_4_ = uStack_1dc - uStack_1e4;
                                  iVar7 = (iStack_1e0 - iStack_1e8) -
                                          (uint)(uStack_1dc < uStack_34._0_4_);
                                  if (((0 < iVar7) || ((iVar7 == 0 && (uStack_34._0_4_ != 0)))) ||
                                     (cStack_1bf == '\0')) break;
                                  uStack_34 = uVar18;
                                  (*(code *)PTR_pthread_cond_wait_004475cc)(auStack_210,auStack_228)
                                  ;
                                  uVar18 = uStack_34;
                                }
                                pkg_status_set_active
                                          (puStack_2bc,*(undefined4 *)(iStack_2b0 + 0x6c));
                                pkg_status_set_active(uStack_2c0,*(undefined4 *)(iStack_2b0 + 0x6c))
                                ;
                                uVar18 = CONCAT44(uStack_34._0_4_,uStack_34._4_4_);
                              }
                              uVar14 = uStack_1c4;
                              uStack_34 = uVar18;
                              if (uStack_1c4 == 0) {
                                if (cStack_1c8 == '\0') {
                                  iVar11 = (uint)(uStack_34._0_4_ + uStack_1f4 < uStack_34._0_4_) +
                                           iVar7 + iStack_1f8;
                                  iVar16 = (int)uVar15 >> 0x1f;
                                  if ((iStack_1e0 < iVar11) ||
                                     ((iVar11 == iStack_1e0 &&
                                      (uStack_1dc < uStack_34._0_4_ + uStack_1f4)))) {
                                    uStack_34._0_4_ = uStack_1dc - uStack_1f4;
                                    iVar7 = (iStack_1e0 - iStack_1f8) -
                                            (uint)(uStack_1dc < uStack_34._0_4_);
                                  }
                                  if ((iVar16 < iVar7) ||
                                     ((uVar14 = uStack_34._0_4_, iVar7 == iVar16 &&
                                      (uVar15 < uStack_34._0_4_)))) {
                                    uVar14 = uVar15;
                                    iVar7 = iVar16;
                                  }
                                  iVar7 = (uint)(uVar14 + uStack_27c < uVar14) + iVar7 + iStack_280;
                                  if ((iStack_290 < iVar7) ||
                                     ((iVar7 == iStack_290 && (uStack_28c < uVar14 + uStack_27c))))
                                  {
                                    uVar14 = uStack_28c - uStack_27c;
                                  }
                                  uStack_34._0_4_ = iStack_1f8;
                                  uStack_34._4_4_ = uStack_1f4;
                                  (*(code *)PTR_pthread_mutex_unlock_00447764)(auStack_228);
                                  uVar5 = 0;
                                  (*(code *)PTR_lseek64_00447544)(auStack_298[0]);
                                  uVar15 = (*(code *)PTR_write_004476a0)
                                                     (auStack_298[0],iVar4 + iVar9,uVar14);
                                  if (-1 < (int)uVar15) {
                                    uVar14 = (*(code *)PTR_pthread_mutex_lock_00447690)(auStack_228)
                                    ;
                                    if (uVar14 == 0) {
                                      iVar7 = (int)uVar15 >> 0x1f;
                                      iStack_280 = (uint)(uStack_27c + uVar15 < uStack_27c) +
                                                   iStack_280 + iVar7;
                                      iStack_1e8 = (uint)(uStack_1e4 + uVar15 < uStack_1e4) +
                                                   iStack_1e8 + iVar7;
                                      uStack_1f4 = uVar15 + uStack_1f4;
                                      iStack_1f8 = (uint)(uStack_1f4 < uVar15) + iVar7 + iStack_1f8;
                                      if ((iStack_1e0 <= iStack_1f8) &&
                                         ((iStack_1e0 != iStack_1f8 || (uStack_1dc <= uStack_1f4))))
                                      {
                                        uStack_1f4 = 0;
                                        iStack_1f8 = 0;
                                      }
                                      uStack_27c = uStack_27c + uVar15;
                                      uStack_1e4 = uStack_1e4 + uVar15;
                                      (*(code *)PTR_pthread_cond_broadcast_00447830)(auStack_210);
                                      if ((iStack_290 <= iStack_280) &&
                                         ((iStack_290 != iStack_280 || (uStack_28c <= uStack_27c))))
                                      {
                                        uStack_1c0 = 1;
                                        cStack_22f = '\x01';
                                      }
                                      (*(code *)PTR_pthread_mutex_unlock_00447764)(auStack_228);
                                      goto code_r0x00423dc4;
                                    }
                                    goto code_r0x00423c48;
                                  }
                                  puVar6 = (uint *)(*(code *)PTR___errno_location_004476c0)();
                                  iVar7 = iStack_2ac;
                                  uVar14 = *puVar6;
                                  if (uVar14 != 4) {
                                    uStack_2c = uStack_2a8;
                                    uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                                    (*(code *)PTR_snprintf_004477b0)
                                              (iVar7,uStack_2c,&UNK_004355e4,uVar3,uVar5);
                                    if (uVar14 != 0) goto code_r0x00423d80;
                                  }
                                }
                                else {
                                  (*(code *)PTR_pthread_mutex_unlock_00447764)(auStack_228);
                                  (*(code *)PTR_syslog_004477f0)(4,&UNK_004355cc);
                                  cStack_22f = '\x01';
                                }
                                uVar15 = 0;
                                goto code_r0x00423dc4;
                              }
                              (*(code *)PTR_pthread_mutex_unlock_00447764)(auStack_228);
                              iVar4 = iStack_2ac;
                              uStack_2c = uStack_2a8;
                              uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                              (*(code *)PTR_snprintf_004477b0)(iVar4,uStack_2c,&UNK_00434dd4,uVar3);
                              cStack_22e = '\x01';
                            }
                            else {
                              (*(code *)PTR_syslog_004477f0)(6,&UNK_00435588);
                              uVar14 = (*(code *)PTR_pthread_mutex_lock_00447690)(param_1 + 0x70);
                              iVar7 = iStack_2ac;
                              puVar12 = PTR_pthread_mutex_unlock_00447764;
                              if (uVar14 == 0) {
                                *(uint *)(param_1 + 4) = *(uint *)(param_1 + 4) & 0xffffbfff;
                                (*(code *)puVar12)(param_1 + 0x70);
                                uVar14 = 1;
                                goto code_r0x0042384c;
                              }
                              uStack_2c = uStack_2a8;
                              uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                              puVar12 = &UNK_0043559c;
code_r0x00423c74:
                              (*(code *)PTR_snprintf_004477b0)(iVar7,uStack_2c,puVar12,uVar3);
                            }
code_r0x00423d80:
                            uVar3 = *(undefined4 *)(param_1 + 0x1d8);
                            puVar12 = &UNK_00435604;
                            goto code_r0x00423d88;
                          }
                          uVar15 = 0;
code_r0x00423dc4:
                          iVar9 = iVar9 + uVar15;
                        }
                      }
                      goto code_r0x00423de0;
                    }
                  } while (uVar14 == 0xb);
                  (*(code *)PTR_snprintf_004477b0)
                            (iStack_2ac,uStack_2a8,&UNK_00434fa4,uStack_50,uVar14);
                  uVar3 = *(undefined4 *)(param_1 + 0x1d8);
                  cStack_22d = '\x01';
                  puVar12 = &UNK_00434fcc;
                  pcVar17 = (code *)PTR_pkg_log_debug_0044731c;
                  goto code_r0x00422ba0;
                }
                pkg_log_warning(*(undefined4 *)(param_1 + 0x1d8),&UNK_00434e70,uVar14);
                puVar12 = &UNK_00434ea0;
code_r0x00422a90:
                (*(code *)PTR_snprintf_004477b0)(iStack_2ac,uStack_2a8,puVar12,uVar3,uVar14);
                cStack_22d = '\x01';
              }
              else {
                pkg_log_warning(*(undefined4 *)(param_1 + 0x1d8),&UNK_00434e04,uVar14);
                iVar4 = iStack_2ac;
                uStack_2c = uStack_2a8;
                uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
                (*(code *)PTR_snprintf_004477b0)(iVar4,uStack_2c,&UNK_00434e30,uVar3);
                cStack_22d = '\x01';
              }
              goto code_r0x00423df4;
            }
            uStack_2c = uStack_2a8;
            uVar3 = (*(code *)PTR_strerror_00447428)();
            (*(code *)PTR_snprintf_004477b0)(iVar4,uStack_2c,&UNK_00434dd4,uVar3);
            cStack_22e = '\x01';
            pkg_log_error(*(undefined4 *)(param_1 + 0x1d8),&UNK_00434df4,__FUNCTION___24583,
                          uStack_1c4);
            uVar14 = uStack_1c4;
            if (uStack_1c4 != 0) goto code_r0x00423df4;
code_r0x00423ec4:
            if ((iStack_48 != 0 || uStack_44 != 0) && (iStack_48 <= iStack_278)) {
              if (iStack_278 == iStack_48) {
                if (uStack_274 < uStack_44) goto code_r0x004240f0;
                uVar5 = *(uint *)(param_1 + 4);
              }
              else {
                uVar5 = *(uint *)(param_1 + 4);
              }
              if ((uVar5 & 0x100000) != 0) {
                iVar4 = pkg_restart_ok(param_1,&uStack_2c0);
                if (iVar4 == 0) goto code_r0x004240f0;
              }
              cStack_22d = '\x01';
              uVar5 = uStack_44 + *(int *)(param_1 + 0xf4);
              iStack_48 = (uint)(uVar5 < uStack_44) + iStack_48 + *(int *)(param_1 + 0xf0);
              uStack_44 = uVar5;
              (*(code *)PTR_snprintf_004477b0)(iStack_2ac,uStack_2a8,&UNK_004356a4);
              uVar14 = 0x16;
              iVar9 = iStack_4c;
              goto code_r0x004240c8;
            }
            goto code_r0x004240f0;
          }
code_r0x00424100:
          iVar9 = iStack_38;
          iVar4 = iStack_40;
          pkg_log_info(*(undefined4 *)(param_1 + 0x1d8),&UNK_00435704);
          pkg_status_set_inactive(puStack_2bc,*(undefined4 *)(iVar9 + 0x6c));
          pkg_status_set_inactive(uStack_2c0,*(undefined4 *)(iVar9 + 0x6c));
          pkg_status_report(param_1,param_2,puStack_2bc);
          uVar14 = (*(code *)PTR_pthread_mutex_lock_00447690)(auStack_228);
          if (uVar14 == 0) {
            uStack_1c0 = 1;
            (*(code *)PTR_pthread_cond_broadcast_00447830)(auStack_210);
            pkg_log_info(*(undefined4 *)(param_1 + 0x1d8),&UNK_00435730);
            while (cStack_1bf != '\0') {
              uVar3 = (*(code *)PTR_tu_uptime_secs_00447620)();
              uVar14 = pkg_check_timeout(param_1,&uStack_2c0,uVar3);
              if (uVar14 != 0) {
                bVar1 = true;
                goto code_r0x0042441c;
              }
              aiStack_484[0] = (*(code *)PTR_time_0044769c)(0);
              aiStack_484[0] = aiStack_484[0] + 2;
              aiStack_484[1] = 0;
              pkg_log_trace(*(undefined4 *)(param_1 + 0x1d8),&UNK_00435778);
              (*(code *)PTR_pthread_cond_timedwait_00447524)(auStack_210,auStack_228,aiStack_484);
            }
            pkg_log_info(*(undefined4 *)(param_1 + 0x1d8),&UNK_004357a4);
            (*(code *)PTR_pthread_mutex_unlock_00447764)(auStack_228);
            pkg_status_report(param_1,param_2,puStack_2bc);
            if (uStack_1c4 != 0) {
              uVar3 = (*(code *)PTR_strerror_00447428)();
              (*(code *)PTR_snprintf_004477b0)(iVar4,16000,&UNK_00434dd4,uVar3);
              cStack_22e = '\x01';
              uVar14 = uStack_1c4;
              goto code_r0x004221bc;
            }
            uVar14 = (*(code *)PTR_lib2sp_get_state_004478ac)(iStack_2b8,&iStack_490);
            if (uVar14 == 0) {
              if (iStack_490 == 5) {
                (*(code *)PTR_close_00447498)(iStack_270);
                (*(code *)PTR_close_00447498)(iStack_26c);
                (*(code *)PTR_free_004478d4)(iVar4);
                (*(code *)PTR_lib2sp_destroy_context_004473d8)(iStack_2b8);
                if (iStack_488 != 0) {
                  (*(code *)PTR_lib2sp_vfy_destroy_context_004475d0)();
                }
                (*(code *)PTR_close_00447498)(auStack_298[0]);
                pkg_spool_cleanup(param_1,auStack_228);
                pkg_util_http_cleanup(&uStack_258);
                *(undefined4 *)(param_1 + 0xdc) = 0;
                *param_6 = 0;
                pkg_log_trace(*(undefined4 *)(param_1 + 0x1d8),&UNK_00435828);
                return 0;
              }
              (*(code *)PTR_snprintf_004477b0)(iVar4,16000,&UNK_004357fc);
              bVar1 = false;
              uVar14 = 0xca;
              goto code_r0x0042441c;
            }
            uVar5 = (*(code *)PTR_strerror_00447428)(uVar14);
            puVar12 = &UNK_004357e0;
          }
          else {
            uVar5 = (*(code *)PTR_strerror_00447428)(uVar14);
            puVar12 = &UNK_00433fa4;
          }
          goto code_r0x00424198;
        }
        uStack_34._4_4_ = *(undefined4 *)(param_4 + 0x2c);
        uVar3 = (*(code *)PTR_strerror_00447428)(uVar14);
        (*(code *)PTR_snprintf_004477b0)(iVar4,16000,&UNK_00434d2c,uStack_34._4_4_,uVar3);
        goto code_r0x004221bc;
      }
    }
    else {
      puVar6 = (uint *)(*(code *)PTR___errno_location_004476c0)();
      uVar14 = *puVar6;
      uVar5 = (*(code *)PTR_strerror_00447428)(uVar14);
      puVar12 = &UNK_00434a98;
code_r0x00424198:
      (*(code *)PTR_snprintf_004477b0)(iVar4,16000,puVar12,uVar5);
code_r0x004221bc:
      bVar1 = false;
    }
code_r0x0042441c:
    if (iStack_2b4 != 0) {
      if (!bVar1) {
        iVar9 = (*(code *)PTR_pthread_mutex_lock_00447690)(auStack_228);
        if (iVar9 != 0) {
          uVar3 = (*(code *)PTR_strerror_00447428)(iVar9);
          (*(code *)PTR_syslog_004477f0)(3,&UNK_00433fa4,uVar3);
        }
      }
      if ((uStack_1c4 == 0) && (uStack_1c4 = uVar14, uVar14 == 0)) {
        uStack_1c4 = 0xca;
      }
      (*(code *)PTR_pthread_cond_broadcast_00447830)(auStack_210);
      while (cStack_1bf != '\0') {
        (*(code *)PTR_pthread_cond_wait_004475cc)(auStack_210,auStack_228);
      }
      (*(code *)PTR_pthread_mutex_unlock_00447764)(auStack_228);
    }
    if (iStack_2b8 != 0) {
      iVar9 = (*(code *)PTR_lib2sp_get_state_004478ac)(iStack_2b8,&iStack_490);
      if ((iVar9 == 0) && (iStack_490 == 6)) {
        iVar9 = (*(code *)PTR_lib2sp_get_error_00447614)(iStack_2b8,&iStack_48c,iVar4,16000);
        if ((iVar9 != 0) || (iStack_48c != 7)) goto code_r0x00424530;
        uVar14 = 0xc;
code_r0x00424550:
        if (iStack_490 != 6) {
          (*(code *)PTR_lib2sp_signal_error_004475d8)(iStack_2b8,8,iVar4);
        }
      }
      else {
code_r0x00424530:
        if (uVar14 != 0x91) goto code_r0x00424550;
        (*(code *)PTR_lib2sp_signal_timeout_00447588)(iStack_2b8);
      }
      (*(code *)PTR_lib2sp_destroy_context_004473d8)(iStack_2b8);
      iStack_2b8 = 0;
    }
    if (iStack_488 != 0) {
      (*(code *)PTR_lib2sp_vfy_destroy_context_004475d0)();
      iStack_488 = 0;
    }
    if (-1 < iStack_270) {
      (*(code *)PTR_close_00447498)();
    }
    if (-1 < iStack_26c) {
      (*(code *)PTR_close_00447498)();
    }
    uVar5 = uVar14;
    if (cStack_22e != '\0') {
      uVar5 = uStack_1c4;
    }
    iVar9 = iStack_2b4;
    if (uVar5 != 0) goto code_r0x00424608;
    puVar12 = &UNK_00435850;
    uVar3 = 1999;
  }
  else {
    puVar12 = &UNK_00434a68;
    uVar3 = 0x65c;
  }
  iVar9 = (*(code *)PTR___assert_00447404)(puVar12,&UNK_00434490,uVar3,__PRETTY_FUNCTION___24624);
code_r0x00424608:
  if (iVar9 != 0) {
    (*(code *)PTR_close_00447498)(auStack_298[0]);
    pkg_spool_cleanup(param_1,auStack_228);
  }
  pkg_util_http_cleanup(&uStack_258);
  *(undefined4 *)(param_1 + 0xdc) = 0;
  *param_6 = iVar4;
  pkg_log_warning(*(undefined4 *)(param_1 + 0x1d8),&UNK_0043585c,param_6);
  return uVar5;
}



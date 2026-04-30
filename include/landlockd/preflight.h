#ifndef LANDLOCKD_PREFLIGHT_H
#define LANDLOCKD_PREFLIGHT_H

#define LANDLOCKD_PREFLIGHT_ABI_FLOOR 1
#define LANDLOCKD_PREFLIGHT_STACKING_MIN_ABI 1

struct landlockd_preflight_report {
  int abi_version;
  int required_abi_floor;
  int meets_abi_floor;
  int stacking_supported;
  int probe_errno;
  int seccomp_user_notif_supported;
  int seccomp_probe_errno;
};

int landlockd_preflight_run(int required_abi_floor,
                            struct landlockd_preflight_report *out);
int landlockd_preflight_probe_seccomp_user_notif(
    struct landlockd_preflight_report *out);

#endif

# Example rule attribution

The `.yml` files in this directory are unmodified rules from the
[SigmaHQ rule repository](https://github.com/SigmaHQ/sigma), bundled so the
app is useful the moment you land on it. They are licensed under the
[Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License);
each file carries its original `author` field.

| File | Upstream path |
|---|---|
| `hash_imphash_sharpevtmute.yml` | `rules/windows/image_load/image_load_hktl_sharpevtmute.yml` |
| `ip_bare_not_zeek_rdp.yml` | `rules/network/zeek/zeek_rdp_public_listener.yml` |
| `domain_dns_xmr_mining.yml` | `rules/network/dns/net_dns_pua_cryptocoin_mining_xmr.yml` |
| `artifact_sysnative_filters.yml` | `rules/windows/process_creation/proc_creation_win_susp_sysnative.yml` |
| `relational_fieldref_delete_own_image.yml` | `rules/windows/file/file_delete/file_delete_win_delete_own_image.yml` |
| `tool_rubeus_pe_metadata.yml` | `rules/windows/process_creation/proc_creation_win_hktl_rubeus.yml` |
| `ttp_dump64_renamed_procdump.yml` | `rules/windows/process_creation/proc_creation_win_dump64_defender_av_bypass_rename.yml` |

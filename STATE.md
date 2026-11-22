# STATE.md - PromptGuard (GenLayer Intelligent Contract)

## Status saat ini
- Fase: kode selesai, uji lokal LULUS 25/25, lint LULUS (3 checks), review akhir Groq selesai. Repo dibuat dan di-push. Studio deploy BELUM dilakukan (butuh browser task induk).
- JANGAN SUBMIT ke portal GenLayer tanpa persetujuan Monch.

## SOP dan skill yang dibaca utuh sebelum kerja
- ~/workspace/AGENT_SOP.md (utuh)
- ~/AGENTS.md (bootloader, utuh)
- ~/workspace/AGENTS.md (aturan workspace, utuh)
- ~/workspace/multi-wallet-sop.md (utuh; tidak ada kerja multi-wallet di build ini)
- Skill: security_audit, evm_audit (pola audit diadaptasi ke Python Intelligent Contracts)
- Spesifikasi: ~/workspace/garapan-genlayer/BUILDER-IDEAS-2026-11-22.md (Ide 3, utuh)
- Blueprint mengikat: ~/workspace/garapan-genlayer/BUILD-BLUEPRINT-2026-11-22.md (utuh)
- Pola kontrak terbukti jalan: ~/workspace/garapan-genlayer/fairdeal-escrow/ (contracts/fairdeal.py, tests/test_fairdeal.py) dan ~/workspace/garapan-genlayer/genlayer-median-oracle/ (contracts/median_oracle.py, tests/test_median_oracle.py, STATE.md)

## Keputusan desain (mengikuti blueprint, bukan desain sendiri)
- Validator kustom via gl.vm.run_nondet_unsafe(leader_fn, validator_fn). Validator menjalankan ulang screen, mem-parse kedua JSON, dan memeriksa verdict sama persis DAN selisih confidence paling banyak 15 secara programatik. prompt_comparative, field_eq, numeric_tolerance, run_nondet_safe TIDAK dipakai (prompt_comparative tidak dipakai karena blueprint memerintahkan validator programatik; field_eq, numeric_tolerance, run_nondet_safe tidak ada di dokumen resmi).
- Pemeriksaan pola tolak jalan dulu, sebelum model bahasa dipanggil: input di-lowercase, tiap frasa di BLOCKED_PATTERNS dicocokkan sebagai substring. Cocok berarti malicious dengan confidence 95, tanpa panggilan model. Daftar mencakup override instruksi, ekstraksi instruksi, framing jailbreak, dan pemaksaan hasil.
- screen_batch memeriksa tiap teks dengan panggilan model dan validator sendiri, bukan satu panggilan untuk seluruh batch, supaya satu teks tidak melemahkan pemeriksaan teks lain. Validator tiap item bisa dipilih lewat run_validator(index=...) di tes lokal.
- Statistik hanya mencatat pemeriksaan yang selesai; panggilan yang revert tidak tercatat.
- Error model yang diharapkan memakai prefix [EXPECTED] dan dibandingkan persis oleh validator; error lain berarti disagree. Jalur ini BISA diuji di Direct Mode lewat run_validator(leader_error=...), tidak seperti Median Oracle.

## Verifikasi prasyarat (dilakukan sebelum koding)
- gl.vm.run_nondet_unsafe dan gl.nondet.exec_prompt ADA di bundle lokal (dipakai FairDeal dan Median Oracle, tes keduanya lolos). Pola validator kustom dikonfirmasi dari dokumen resmi GenLayer (Equivalence Principle) dan preseden Median Oracle.
- Semantik mock harness dibaca dari source genlayer-test 0.29.2 sebelum menulis tes: mock_llm memakai pola pertama yang cocok (first match wins), run_validator(index=...) memilih validator ke-n dari panggilan run_nondet, dan mock JSON valid di-parse otomatis menjadi dict oleh wasi_mock. _parse_screen menangani dict dan string.
- Parameter list[str] pada screen_batch DIBUKTIKAN jalan di bundle lokal (tes batch lolos), bukan asumsi.

## Uji lokal (genlayer-test Direct Mode, 22 Nov 2026)
- 25/25 LULUS dalam 0,90 detik. Cakupan: get_stats awal nol, teks bersih, injeksi jelas dicegat pola tolak sebelum LLM (mock yang menjawab clean tetap kalah oleh pola), pola tolak case-insensitive tanpa mock sama sekali (membuktikan tidak ada panggilan model), injeksi halus tertangkap model, kata kunci berbahaya dalam konteks sah dinilai bersih, suspicious tercatat di stats, teks kosong revert, teks terlalu panjang revert, model mengembalikan bukan JSON revert, verdict tidak valid revert, confidence di luar 0-100 revert, reason hilang revert, validator menerima hasil sama, validator menerima selisih confidence 12 dan 15 (batas inklusif), validator menolak selisih 16, validator menolak verdict berbeda, validator menolak leader yang berbohong, validator setuju pada error [EXPECTED] yang sama, validator tidak setuju saat leader error tapi validator sukses, screen_batch campuran (bersih, halus, pola tolak) dengan urutan dan stats benar plus kedua validator batch True, batch kosong revert, batch 11 item revert, batch berisi item kosong revert.
- Batasan uji: kontrak diuji sebagai salinan yang byte-identik kecuali header (pin SDK 1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6, satu-satunya runner di bundle GenVM v0.3.0-rc7) dan dua penyesuaian API era lama (from genlayer import * sebagai ganti from genlayer.types import *, gl.Contract sebagai ganti gl.contract.Contract). Kontrak kirim tetap memakai header v0.4.0 dan pin kzybg95x1gn21dw72m7hyg0maaap04n4nx55j9yt6fkdqxtz6bz0. Bukti deploy Studio tetap menjadi cek otoritatif untuk pin kirim.
- Batasan uji tambahan: tes memakai respons model mock, bukan model live. Kualitas klasifikasi di Studio bergantung pada model yang dipakai Studio.

## Lint
- genvm-lint check LULUS (3 checks). Validasi schema linter gagal karena linter hanya punya cache GenVM v0.3.0-rc7 dan tidak ada tarball SDK untuk pin kirim: "filename 'runners/py-genlayer/kz/ybg95x1gn21dw72m7hyg0maaap04n4nx55j9yt6fkdqxtz6bz0.tar' not found". Bukan salah kontrak, template resmi wizard_of_coin.py gagal dengan pola yang sama (preseden FairDeal dan Median Oracle).

## Review akhir Groq (22 Nov 2026, openai/gpt-oss-120b)
- Percobaan 1 (max-tokens 2048): tidak menghasilkan isi (finish_reason length, seluruh 2048 token habis untuk reasoning, content kosong), jadi tidak ada verdict. Jejak reasoning-nya sempat mempermasalahkan validator yang menjalankan ulang leader_fn.
- Percobaan 2 (prompt ringkas, max-tokens 4096): VERDICT SHIP, 0 temuan.
- DITOLAK (keberatan dari jejak reasoning percobaan 1): "validator tidak boleh menjalankan ulang leader_fn karena nondet". Salah. Pola resmi GenLayer (Equivalence Principle) menetapkan validator menjalankan ulang komputasi leader dan membandingkan hasilnya; strict_eq bawaan SDK melakukan hal yang sama lewat spawn_sandbox; Median Oracle memakai pola identik dan tes lokalnya membuktikan validator menerima hasil dalam pita dan menolak di luar pita. Membandingkan leader dengan dirinya sendiri akan menjadi pemeriksaan kosong. _handle_leader_error yang menjalankan ulang leader_fn mengikuti pola yang sama dan sudah dipakai Median Oracle.

## Audit teks
- README.md: 0 em/en dash, 0 klise AI, 0 pola retoris (dicek dengan rg sesuai AGENT_SOP.md).

## File aktif
- contracts/promptguard.py (kontrak utama)
- tests/test_promptguard.py (25 uji lokal)
- README.md
- STATE.md
- LICENSE (MIT)

## Alamat / hash
- Studio deploy: belum ada (menunggu browser task)
- Repo GitHub: https://github.com/Yogii123-qw/genlayer-promptguard
- Commit: 857eb12 (master, terverifikasi di remote)

## Langkah berikutnya
1. Serahkan ke induk untuk uji deploy Studio lewat cloud browser (akun dev Studio, bukan wallet Monch). Tempel kontrak, deploy tanpa argumen konstruktor, panggil screen dengan teks bersih dan teks injeksi sampai ada transaksi ACCEPTED dan consensus tercapai. Catat alamat kontrak dan tx hash.
2. Setelah deploy Studio terverifikasi, serahkan draf submission ke Monch untuk disetujui. JANGAN submit ke Portal tanpa itu.

{
  "targets": [ {
    "target_name": "pqp",
    "include_dirs": [
      "<!(node -e \"console.log(process.cwd())\")/Picnic"
    ],
    "libraries": [
      "<!(node -e \"console.log(process.cwd())\")/Picnic/VisualStudio/x64/Debug/libpicnic/libpicnic.lib",
      "-lbcrypt.lib",
      "-lmsvcrt.lib"
    ],
    "sources": [
      "./src/pqp.c"
    ]
  } ]
}

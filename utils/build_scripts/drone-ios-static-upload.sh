tmpdir=ios-deps-${DRONE_COMMIT}
mkdir -p $tmpdir/lib
mkdir -p $tmpdir/include

# Merge the arm64 and simulator libs into a single multi-arch merged lib:
lipo -create build/{arm64,sim64}/src/wallet/api/libwallet_merged.a -o $tmpdir/lib/libwallet_api.a

cp src/wallet/api/wallet2_api.h $tmpdir/include

filename=ios-deps-${DRONE_COMMIT}.tar.xz
XZ_OPTS="--threads=6" tar --dereference -cJvf $filename $tmpdir

# sftp doesn't have any equivalent to mkdir -p, so we have to split the above up into a chain of
# -mkdir a/, -mkdir a/b/, -mkdir a/b/c/, ... commands.  The leading `-` allows the command to fail
# without error.
upload_dirs=(${upload_to//\// })
mkdirs=
dir_tmp=""
for p in "${upload_dirs[@]}"; do
    dir_tmp="$dir_tmp$p/"
    mkdirs="$mkdirs
-mkdir $dir_tmp"
done
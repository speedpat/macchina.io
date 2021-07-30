basedir=`pwd`
osname=`uname`
osarch=`uname -m`
export MACCHINA_BASE="$basedir"
export MACCHINA_VERSION=`cat $basedir/VERSION`
export PROJECT_BASE="$MACCHINA_BASE"
export MACCHINA_CODECACHE="$MACCHINA_BASE/server/bin/$osname/$osarch/codeCache"
export POCO_BASE="$MACCHINA_BASE/platform"
if [ $osname = "Darwin" ] ; then
	export DYLD_LIBRARY_PATH=$MACCHINA_CODECACHE:$POCO_BASE/lib/$osname/$osarch:$DYLD_LIBRARY_PATH
	libPath=$DYLD_LIBRARY_PATH
	libPathVar="DYLD_LIBRARY_PATH"
else
	export LD_LIBRARY_PATH=$MACCHINA_CODECACHE:$POCO_BASE/lib/$osname/$osarch:$LD_LIBRARY_PATH
	libPath=$LD_LIBRARY_PATH
	libPathVar="LD_LIBRARY_PATH  "
fi

mkdir -p $MACCHINA_CODECACHE

echo "macchina.io EDGE build environment set."
echo ""
echo "\$MACCHINA_BASE     = $MACCHINA_BASE"
echo "\$PROJECT_BASE      = $PROJECT_BASE"
echo "\$POCO_BASE         = $POCO_BASE"
echo "\$MACCHINA_VERSION  = $MACCHINA_VERSION"
echo "\$$libPathVar = $libPath"
echo ""

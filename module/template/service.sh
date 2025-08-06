DEBUG=@DEBUG@

MODDIR=${0%/*}

cd $MODDIR

while true; do
  ./daemon || exit 1
  # ensure keystore initialized
  sleep 2
done &

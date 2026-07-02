#!/bin/bash
# DarkWatch quick scan helper.
#
# Run on the VM (or via SSH). This script `docker exec`s into the
# darkwatch container, so it's a no-op from your dev workstation
# unless you're SSHed in.
#
# Usage: ./scan.sh <command> [args]

CONTAINER="darkwatch"
CMD="docker exec $CONTAINER python3 darkwatch.py -c config.json"

case "$1" in
    url)
        # Crawl single URL: ./scan.sh url http://target.onion [depth]
        DEPTH="${3:-2}"
        $CMD --url "$2" --depth "$DEPTH"
        ;;
    all)
        # Crawl all URLs in database: ./scan.sh all
        $CMD --crawl-all
        ;;
    import)
        # Import URLs from file: ./scan.sh import urls.txt
        $CMD --import-urls "/loot/$2"
        ;;
    find)
        # Show findings: ./scan.sh find [keyword] [min-score]
        ARGS="--findings"
        [ -n "$2" ] && ARGS="$ARGS --keyword $2"
        [ -n "$3" ] && ARGS="$ARGS --min-score $3"
        $CMD $ARGS
        ;;
    report)
        # Generate report: ./scan.sh report [min-score]
        ARGS="--report"
        [ -n "$2" ] && ARGS="$ARGS --min-score $2"
        $CMD $ARGS
        ;;
    stats)
        # Show stats: ./scan.sh stats
        $CMD --stats
        ;;
    test)
        # Test Tor: ./scan.sh test
        $CMD --test-tor
        ;;
    db)
        # Raw DB query: ./scan.sh db "SELECT * FROM findings"
        docker exec $CONTAINER sqlite3 -header -column data/darkwatch.db "$2"
        ;;
    *)
        echo "DarkWatch Scanner"
        echo "═══════════════════════════════════════"
        echo ""
        echo "Usage: ./scan.sh <command> [args]"
        echo ""
        echo "Commands:"
        echo "  url <onion_url> [depth]     Crawl a single .onion site"
        echo "  all                         Crawl all URLs in database"
        echo "  import <file>               Import URLs from file in ./loot/"
        echo "  find [keyword] [min-score]  Search findings"
        echo "  report [min-score]          Generate JSON + text report"
        echo "  stats                       Show database statistics"
        echo "  test                        Test Tor connectivity"
        echo "  db \"SQL query\"              Run raw SQL query"
        echo ""
        echo "Examples:"
        echo "  ./scan.sh url http://xyz.onion"
        echo "  ./scan.sh url http://xyz.onion 3"
        echo "  ./scan.sh find example.com 80"
        echo "  ./scan.sh report 50"
        echo "  ./scan.sh db \"SELECT * FROM findings WHERE severity='critical'\""
        echo ""
        ;;
esac

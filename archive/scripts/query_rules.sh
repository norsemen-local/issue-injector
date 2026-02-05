#!/bin/bash
# Analytics Rules Query Helper
# Usage: ./query_rules.sh [command]

RULES_FILE="analytics_rules.jsonl"

case "$1" in
    "created")
        echo "📊 Alerts Created:"
        cat $RULES_FILE | jq -r 'select(.alert_created == true) | "\(.rule_id): \(.name) → \(.alert_json_file)"'
        ;;
    "uncreated-high")
        echo "🎯 High Severity Rules Without Alerts:"
        cat $RULES_FILE | jq -r 'select(.alert_created == false and .severity == "High") | "\(.rule_id): \(.name)"'
        ;;
    "uncreated-medium")
        echo "🎯 Medium Severity Rules Without Alerts:"
        cat $RULES_FILE | jq -r 'select(.alert_created == false and .severity == "Medium") | "\(.rule_id): \(.name)"'
        ;;
    "stats")
        echo "📈 Analytics Rules Coverage Statistics:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        TOTAL=$(cat $RULES_FILE | wc -l | xargs)
        CREATED=$(cat $RULES_FILE | jq 'select(.alert_created == true)' | wc -l | xargs)
        UNCREATED=$((TOTAL - CREATED))
        PERCENT=$(awk "BEGIN {printf \"%.2f\", ($CREATED/$TOTAL)*100}")
        
        echo "Total Rules: $TOTAL"
        echo "Alerts Created: $CREATED ($PERCENT%)"
        echo "Remaining: $UNCREATED"
        echo ""
        echo "By Severity (Uncreated):"
        echo "  High:          $(cat $RULES_FILE | jq -r 'select(.alert_created == false and .severity == "High")' | wc -l | xargs)"
        echo "  Medium:        $(cat $RULES_FILE | jq -r 'select(.alert_created == false and .severity == "Medium")' | wc -l | xargs)"
        echo "  Low:           $(cat $RULES_FILE | jq -r 'select(.alert_created == false and .severity == "Low")' | wc -l | xargs)"
        echo "  Informational: $(cat $RULES_FILE | jq -r 'select(.alert_created == false and .severity == "Informational")' | wc -l | xargs)"
        ;;
    "find")
        if [ -z "$2" ]; then
            echo "Usage: ./query_rules.sh find <search_term>"
            exit 1
        fi
        echo "🔍 Searching for: $2"
        cat $RULES_FILE | jq --arg search "$2" 'select(.name | contains($search)) | {rule_id, name, severity, alert_created, alert_json_file}'
        ;;
    "rule")
        if [ -z "$2" ]; then
            echo "Usage: ./query_rules.sh rule <rule_id>"
            exit 1
        fi
        echo "📋 Rule Details:"
        cat $RULES_FILE | jq --arg id "$2" 'select(.rule_id == ($id | tonumber))'
        ;;
    *)
        echo "Analytics Rules Query Helper"
        echo ""
        echo "Commands:"
        echo "  created          - List all rules with created alerts"
        echo "  uncreated-high   - List high severity rules without alerts"
        echo "  uncreated-medium - List medium severity rules without alerts"
        echo "  stats            - Show coverage statistics"
        echo "  find <term>      - Search for rules by name"
        echo "  rule <id>        - Show details for specific rule ID"
        echo ""
        echo "Examples:"
        echo "  ./query_rules.sh stats"
        echo "  ./query_rules.sh find Mimikatz"
        echo "  ./query_rules.sh rule 17"
        ;;
esac

## UI Theme Recommendations

### Primary Theme: Professional Dark Mode

**Color Palette**: [aufaitux](https://www.aufaitux.com/blog/cybersecurity-dashboard-ui-ux-design/)
- **Background**: Deep charcoal (#1E1E1E) or dark blue-grey (#1A1F2E) - not pure black to reduce eye strain
- **Surface/Cards**: Slightly lighter grey (#252525 or #242B3D)
- **Primary Accent**: Cyan/Blue (#00D9FF or #4A9EFF) - for interactive elements
- **Text**: Off-white (#E5E5E5) for primary, muted grey (#A0A0A0) for secondary
- **Grid Lines**: Subtle grey (#333333)

**Alert/Status Colors**: [aufaitux](https://www.aufaitux.com/blog/cybersecurity-dashboard-ui-ux-design/)
- Critical/Error: Red (#FF4444)
- Warning: Amber (#FFA500)  
- Success/Safe: Green (#00C853)
- Info: Blue (#2196F3)

**Why Dark Theme**: SOC analysts and forensic investigators work long hours in low-light environments. Dark mode reduces eye strain, improves focus on timeline data, and makes critical findings (highlighted rows) stand out more prominently. [cambridge-intelligence](https://cambridge-intelligence.com/cyber-security-curved-links/)

### Secondary Theme: Light Mode (Optional)

Provide toggle for light mode with:
- Background: Clean white (#FFFFFF)
- Surface: Light grey (#F5F5F5)
- Text: Dark grey (#2C2C2C)
- Same accent colors with adjusted saturation

### Layout Structure

**Three-Panel Design**:
1. **Top Bar** (60px height): File info, global search, theme toggle, export button
2. **Left Sidebar** (300px collapsible): Filter panel with expandable sections [pencilandpaper](https://www.pencilandpaper.io/articles/ux-pattern-analysis-enterprise-filtering)
3. **Main Area**: AG-Grid with column headers and data

***

## Detailed Feature Specifications

### 1. Filtering Features

#### Multi-Level Filter Panel [uxdesign](https://uxdesign.cc/crafting-a-kickass-filtering-ux-beea1798d64b)

**Column-Specific Filters**: [github](https://github.com/Yamato-Security/hayabusa/blob/main/doc/TimelineExplorerAnalysis/TimelineExplorerAnalysis-English.md)
- Display all columns as expandable filter sections [pencilandpaper](https://www.pencilandpaper.io/articles/ux-pattern-analysis-enterprise-filtering)
- Show data type icon next to each column name (text, number, date, boolean)
- Prioritize frequently used forensic fields at top: Timestamp, EventType, Username, Filename, Path

**Filter Types by Data Type**:

**Text Columns**:
- Contains / Does not contain
- Equals / Does not equal
- Starts with / Ends with
- Regex pattern matching
- Case sensitive toggle
- Empty / Not empty

**Numeric Columns**:
- Equals / Not equals
- Greater than / Less than
- Between (range)
- Top N / Bottom N values

**Date/Timestamp Columns**: [securityblue](https://www.securityblue.team/blog/posts/using-timeline-explorer-to-expose-insider-threats)
- Specific date
- Date range (from/to with calendar picker)
- Relative ranges: Last hour, Last 24h, Last 7 days, Last 30 days, Custom
- Before/After specific time
- Time-of-day filters (e.g., events between 9 PM - 6 AM for after-hours activity)

**Multi-Select Filters**: [uxdesign](https://uxdesign.cc/crafting-a-kickass-filtering-ux-beea1798d64b)
- Checkbox list for categorical data (EventType, Extension, etc.)
- Show top 10 most frequent values by default
- "Show All" button to expand [pencilandpaper](https://www.pencilandpaper.io/articles/ux-pattern-analysis-enterprise-filtering)
- Search within filter values
- "Select All" / "Clear All" buttons

#### Filter Behavior [pencilandpaper](https://www.pencilandpaper.io/articles/ux-pattern-analysis-enterprise-filtering)

**Application Methods**:
- **Auto-apply** (Recommended): Filters apply immediately as you select them for <1M rows
- **Manual apply**: "Apply Filters" button for very large files (>1M rows)
- Show pending filter count badge when manual mode

**Filter Persistence**:
- Active filters display as chips/tags at top of grid
- Each chip shows: Column name, operator, value
- Click X on chip to remove individual filter
- "Clear All Filters" button
- Save filter presets with names (e.g., "Suspicious File Creation", "User Logon Events")

**Visual Indicators**:
- Filtered columns show filter icon in header
- Active filter count badge on filter panel toggle
- Show "X of Y rows displayed" below grid

### 2. Sorting Features [thesecuritynoob](https://thesecuritynoob.com/dfir-tools/dfir-tools-timeline-explorer-what-is-it-how-to-use/)

#### Multi-Column Sorting

**Basic Sorting**:
- Click column header to sort ascending
- Click again for descending
- Click third time to remove sort
- Visual indicators: ↑ (ascending), ↓ (descending), ↕ (sortable)

**Advanced Sorting**:
- Hold Shift + Click to add secondary/tertiary sorts
- Show sort priority numbers (1, 2, 3) on sorted columns
- "Clear All Sorting" option in context menu
- Sort panel showing current sort order with drag-to-reorder

**Smart Sorting by Type**:
- **Timestamps**: Chronological (oldest/newest first) [securityblue](https://www.securityblue.team/blog/posts/using-timeline-explorer-to-expose-insider-threats)
- **Text**: Alphabetical with natural sort (file1, file2, file10 not file1, file10, file2)
- **Numbers**: Numeric comparison (not string-based)
- **Mixed types**: Nulls/empties always at bottom
- **Case-sensitive** toggle for text sorting

**Sort Presets for Forensics**:
- "Timeline View" - Sort by Timestamp ascending [securityblue](https://www.securityblue.team/blog/posts/using-timeline-explorer-to-expose-insider-threats)
- "Recent First" - Sort by Timestamp descending
- "Group by Type" - Sort by EventType, then Timestamp
- "Suspicious Activity" - Sort by risk score/flagged items

### 3. Search Features

#### Global Search Bar [github](https://github.com/Yamato-Security/hayabusa/blob/main/doc/TimelineExplorerAnalysis/TimelineExplorerAnalysis-English.md)

**Search Modes**:
- **Simple text search**: Search across all columns
- **Column-specific search**: Dropdown to select which columns to search
- **Regex mode**: Toggle for pattern matching (with syntax helper)
- **Multi-term search**: AND/OR operators support

**Search Options**:
- Case sensitive toggle
- Whole word match toggle
- Highlight matching cells in grid
- Jump to next/previous match (N results, showing result X)

**Forensic-Specific Search Patterns**: [github](https://github.com/Yamato-Security/hayabusa/blob/main/doc/TimelineExplorerAnalysis/TimelineExplorerAnalysis-English.md)
- File extensions: `*.exe`, `*.dll`, `*.ps1`
- IP addresses: Pattern picker for IPv4/IPv6
- Hashes: MD5/SHA1/SHA256 format detection
- Registry paths: Quick regex for HKCU, HKLM patterns
- Common IOCs: Save frequently searched indicators

#### Search Results Display

**Highlighting**:
- Yellow background for matched text
- Bold matched terms
- "Jump to match" buttons (Previous/Next)
- Show match count: "23 matches found"

**Search History**:
- Dropdown showing last 10 searches
- Star/save frequently used searches
- Clear history option

### 4. Column Management

**Column Operations**: [thesecuritynoob](https://thesecuritynoob.com/dfir-tools/dfir-tools-timeline-explorer-what-is-it-how-to-use/)
- **Show/Hide**: Right-click menu or column picker dialog
- **Reorder**: Drag column headers to reposition
- **Resize**: Drag column border or double-click for auto-size
- **Pin**: Freeze columns to left/right (keep Timestamp visible while scrolling)
- **Auto-fit**: Right-click > "Auto-size all columns"

**Column Presets**:
- Save column layouts with names
- Quick toggle: "All Columns", "Essential Only", "Investigation View"
- Reset to default layout

### 5. Additional UX Features

**Keyboard Shortcuts**:
- `Ctrl+F`: Focus global search
- `Ctrl+Shift+F`: Clear all filters
- `Ctrl+E`: Export current view
- `Ctrl+,`: Toggle filter panel
- `Arrow keys`: Navigate cells
- `Page Up/Down`: Fast scroll

**Context Menu** (Right-click on cell):
- Copy cell value
- Copy row
- Filter by this value
- Exclude this value
- Search for this value
- Add to investigation notes

**Performance Indicators**:
- Loading spinner during filter/sort operations
- Progress bar for large file uploads
- Query execution time display
- Row count: "Showing 1,547 of 2,145,899 rows"

**Status Bar** (Bottom of grid):
- Total rows / Filtered rows
- Selected rows count
- File name and size
- Last updated timestamp
- Quick stats: Min/Max/Average for selected numeric column

This design mirrors Timeline Explorer's functionality  while adding modern web UX patterns optimized for forensic analysis workflows you're familiar with from CTF labs and incident response investigations. [thesecuritynoob](https://thesecuritynoob.com/dfir-tools/dfir-tools-timeline-explorer-what-is-it-how-to-use/)
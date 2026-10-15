'use client';
import { DataGrid, type DataGridProps, type GridValidRowModel } from '@mui/x-data-grid';

/** DataGrid with the dashboard's defaults: toolbar with quick search, pagination, auto height. */
export function Grid<R extends GridValidRowModel>(props: DataGridProps<R>) {
  return (
    <DataGrid
      autoHeight
      showToolbar
      disableRowSelectionOnClick
      density="compact"
      getRowHeight={() => 'auto'}
      pageSizeOptions={[25, 50, 100]}
      {...props}
      initialState={{ pagination: { paginationModel: { pageSize: 25 } }, ...props.initialState }}
      slotProps={{ toolbar: { csvOptions: { allColumns: true } }, ...props.slotProps }}
      sx={{ '& .MuiDataGrid-cell': { py: 0.75, display: 'flex', alignItems: 'center' }, ...props.sx }}
    />
  );
}

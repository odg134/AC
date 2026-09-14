#include <Misc/Incl.h>
#include "Splash.h"

namespace Splash
{
    static constexpr int  Width       = 700;
    static constexpr int  Height      = 400;
    static constexpr int  BarH        = 6;
    static constexpr UINT WM_PROGRESS = WM_APP + 1;
    static constexpr UINT WM_QUIT_REQ = WM_APP + 2;

    static HWND Hwnd     = nullptr;
    static int  Progress = 0;

    static LRESULT CALLBACK WndProc( HWND Wnd, UINT Msg, WPARAM Wp, LPARAM Lp )
    {
        switch ( Msg )
        {
        case WM_ERASEBKGND:
            return 1;

        case WM_PROGRESS:
            Progress = static_cast< int >( Wp );
            InvalidateRect( Wnd, nullptr, FALSE );
            return 0;

        case WM_QUIT_REQ:
            DestroyWindow( Wnd );
            return 0;

        case WM_PAINT:
        {
            PAINTSTRUCT Ps;
            HDC Dc = BeginPaint( Wnd, &Ps );

            RECT Rc;
            GetClientRect( Wnd, &Rc );

            // Double-buffer to suppress flicker
            //
            HDC     MemDc  = CreateCompatibleDC( Dc );
            HBITMAP Bmp    = CreateCompatibleBitmap( Dc, Rc.right, Rc.bottom );
            HGDIOBJ OldBmp = SelectObject( MemDc, Bmp );

            HBRUSH Black = CreateSolidBrush( RGB( 0, 0, 0 ) );
            FillRect( MemDc, &Rc, Black );
            DeleteObject( Black );

            int BarW = ( Rc.right * Progress ) / 100;
            if ( BarW > 0 )
            {
                RECT Bar = { 0, Rc.bottom - BarH, BarW, Rc.bottom };
                HBRUSH Cyan = CreateSolidBrush( RGB( 0, 255, 255 ) );
                FillRect( MemDc, &Bar, Cyan );
                DeleteObject( Cyan );
            }

            BitBlt( Dc, 0, 0, Rc.right, Rc.bottom, MemDc, 0, 0, SRCCOPY );
            SelectObject( MemDc, OldBmp );
            DeleteObject( Bmp );
            DeleteDC( MemDc );

            EndPaint( Wnd, &Ps );
            return 0;
        }

        case WM_DESTROY:
            PostQuitMessage( 0 );
            return 0;
        }

        return DefWindowProcW( Wnd, Msg, Wp, Lp );
    }

    bool Create( )
    {
        WNDCLASSEXW Wc{};
        Wc.cbSize        = sizeof( Wc );
        Wc.lpfnWndProc   = WndProc;
        Wc.hInstance     = GetModuleHandleW( nullptr );
        Wc.lpszClassName = L"ACSplash";

        if ( !RegisterClassExW( &Wc ) )
            return false;

        int X = ( GetSystemMetrics( SM_CXSCREEN ) - Width  ) / 2;
        int Y = ( GetSystemMetrics( SM_CYSCREEN ) - Height ) / 2;

        Hwnd = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            L"ACSplash", nullptr,
            WS_POPUP | WS_VISIBLE,
            X, Y, Width, Height,
            nullptr, nullptr, GetModuleHandleW( nullptr ), nullptr
        );

        return Hwnd != nullptr;
    }

    void SetProgress( int Percent )
    {
        if ( Hwnd )
            PostMessageW( Hwnd, WM_PROGRESS, static_cast< WPARAM >( Percent ), 0 );
    }

    void Quit( )
    {
        if ( Hwnd )
            PostMessageW( Hwnd, WM_QUIT_REQ, 0, 0 );
    }

    void Pump( )
    {
        MSG Msg;
        while ( GetMessageW( &Msg, nullptr, 0, 0 ) > 0 )
        {
            TranslateMessage( &Msg );
            DispatchMessageW( &Msg );
        }
    }

    void Destroy( )
    {
        if ( Hwnd )
        {
            DestroyWindow( Hwnd );
            Hwnd = nullptr;
        }
    }
}

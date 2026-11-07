package local.poco.ai;

import android.app.Activity;
import android.net.Uri;
import android.os.Handler;
import android.webkit.*;
import android.util.Base64;
import org.json.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

/** Remote documents never receive a native bridge or direct network capability. */
final class QaBrowser {
  interface Api { String request(String path,String body) throws Exception; }
  private final Activity activity;
  private final Api api;
  private final Handler main=new Handler(android.os.Looper.getMainLooper());
  private final ExecutorService replies=Executors.newSingleThreadExecutor();
  private ScheduledExecutorService polling;
  private WebView view;
  private volatile String session="", origin="";
  private volatile boolean foreground=false;
  QaBrowser(Activity activity,Api api){this.activity=activity;this.api=api;}

  void resume(){foreground=true;polling=Executors.newSingleThreadScheduledExecutor();polling.scheduleWithFixedDelay(()->{
    if(!foreground)return;
    try{JSONObject command=new JSONObject(api.request("/api/browser/next",null));long seq=command.optLong("seq");
      if(seq>0){main.post(()->command(command));}
    }catch(Exception ignored){}
  },0,150,TimeUnit.MILLISECONDS);}
  void pause(){foreground=false;if(polling!=null)polling.shutdownNow();if(!session.isEmpty())event("error","error","MIMO em segundo plano; reabra para retomar");dispose();}
  void destroy(){pause();replies.shutdown();}
  private static String origin(String url){Uri u=Uri.parse(url);String scheme=u.getScheme();int port=u.getPort();return scheme+"://"+u.getHost()+":"+(port<0?("https".equals(scheme)?443:80):port);}
  private static WebResourceResponse blocked(){return new WebResourceResponse("text/plain","UTF-8",403,"Blocked",Collections.emptyMap(),new ByteArrayInputStream(new byte[0]));}
  private void event(String kind,String key,Object value){
    final String id=session;
    replies.execute(()->{try{JSONObject data=new JSONObject().put("id",id).put("kind",kind);if(key!=null)data.put(key,value);api.request("/api/browser/event",data.toString());}catch(Exception ignored){}});
  }
  private void dispose(){if(view!=null){view.stopLoading();view.destroy();view=null;}session="";origin="";}
  private void command(JSONObject cmd){
    if(!foreground)return;
    String kind=cmd.optString("kind"),id=cmd.optString("id");
    if("dispose".equals(kind)){if(id.equals(session))dispose();return;}
    if("evaluate".equals(kind)){
      if(view==null||!id.equals(session))return;
      final long seq=cmd.optLong("seq");
      view.evaluateJavascript(cmd.optString("expression"),value->{
        if(!id.equals(session))return;
        replies.execute(()->{try{Object parsed=new JSONTokener(value).nextValue();api.request("/api/browser/event",new JSONObject().put("id",id).put("kind","result").put("seq",seq).put("value",parsed).toString());}catch(Exception ignored){}});
      });return;
    }
    if(!"start".equals(kind))return;
    dispose();session=id;String url=cmd.optString("url");origin=origin(url);
    view=new WebView(activity);
    WebSettings s=view.getSettings();s.setJavaScriptEnabled(true);s.setDomStorageEnabled(false);s.setDatabaseEnabled(false);
    s.setAllowFileAccess(false);s.setAllowContentAccess(false);s.setAllowFileAccessFromFileURLs(false);s.setAllowUniversalAccessFromFileURLs(false);
    s.setBlockNetworkLoads(true);s.setBlockNetworkImage(true);s.setLoadsImagesAutomatically(false);
    s.setCacheMode(WebSettings.LOAD_NO_CACHE);s.setSupportMultipleWindows(false);s.setJavaScriptCanOpenWindowsAutomatically(false);
    s.setGeolocationEnabled(false);s.setMediaPlaybackRequiresUserGesture(true);s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
    CookieManager.getInstance().setAcceptCookie(false);CookieManager.getInstance().setAcceptThirdPartyCookies(view,false);
    ServiceWorkerController.getInstance().getServiceWorkerWebSettings().setBlockNetworkLoads(true);
    ServiceWorkerController.getInstance().setServiceWorkerClient(new ServiceWorkerClient(){@Override public WebResourceResponse shouldInterceptRequest(WebResourceRequest r){return blocked();}});
    view.setDownloadListener((u,a,c,m,l)->event("error","error","Download não faz parte da navegação"));
    view.setWebChromeClient(new WebChromeClient(){@Override public void onPermissionRequest(PermissionRequest r){r.deny();}});
    view.setWebViewClient(new WebViewClient(){
      @Override public boolean shouldOverrideUrlLoading(WebView v,WebResourceRequest r){return !id.equals(session)||!origin(r.getUrl().toString()).equals(origin)||!"GET".equals(r.getMethod());}
      @Override public void onReceivedSslError(WebView v,SslErrorHandler h,android.net.http.SslError e){h.cancel();}
      @Override public void onReceivedHttpAuthRequest(WebView v,HttpAuthHandler h,String host,String realm){h.cancel();}
      @Override public void onReceivedClientCertRequest(WebView v,ClientCertRequest r){r.cancel();}
      @Override public boolean onRenderProcessGone(WebView v,RenderProcessGoneDetail detail){event("error","error","Processo WebView encerrou; fila preservada");dispose();return true;}
      @Override public void onPageFinished(WebView v,String u){if(id.equals(session)&&!"about:blank".equals(u))event("loaded",null,null);}
      @Override public WebResourceResponse shouldInterceptRequest(WebView v,WebResourceRequest r){
        if(!id.equals(session))return blocked();
        try{
          String target=r.getUrl().toString(),type=r.isForMainFrame()?"Document":"Resource";
          String path=r.getUrl().getPath(),accept=r.getRequestHeaders().get("Accept");
          if(path!=null&&path.matches(".*\\.(m?js)(\\?.*)?$"))type="Script";
          else if(accept!=null&&accept.contains("json"))type="Fetch";
          JSONObject query=new JSONObject().put("id",id).put("kind","fetch").put("url",target).put("method",r.getMethod()).put("type",type);
          JSONObject response=new JSONObject(api.request("/api/browser/event",query.toString()));
          if(response.has("error")||!id.equals(session))return blocked();
          JSONObject raw=response.getJSONObject("headers");Map<String,String> headers=new HashMap<>();
          for(Iterator<String> keys=raw.keys();keys.hasNext();){String k=keys.next();if(!Arrays.asList("content-length","content-encoding","transfer-encoding","set-cookie","connection").contains(k.toLowerCase(Locale.ROOT)))headers.put(k,raw.getString(k));}
          // A second CSP is restrictive even if the response supplied its own policy.
          headers.put("Content-Security-Policy","default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src "+origin+"; img-src 'none'; media-src 'none'; object-src 'none'; worker-src 'none'; child-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'self'");
          headers.put("Cache-Control","no-store");
          String mime=raw.optString("content-type","application/octet-stream").split(";")[0];
          int status=response.optInt("status",200);if(status<200||status>=600||status>=300&&status<400)return blocked();
          return new WebResourceResponse(mime,"UTF-8",status,"Acquired",headers,new ByteArrayInputStream(Base64.decode(response.getString("body"),Base64.DEFAULT)));
        }catch(Exception e){return blocked();}
      }
    });
    view.loadUrl(url);
    main.postDelayed(()->{if(id.equals(session)){event("error","error","Prazo de navegação Android encerrado");dispose();}},(cmd.optInt("seconds",15)+3)*1000L);
  }
}

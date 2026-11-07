package local.poco.ai;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.view.WindowManager;
import android.webkit.*;
import android.widget.Toast;
import org.json.*;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class MainActivity extends Activity {
  private static final String TAG="PocoMimo", HOST="appassets.androidplatform.net";
  private static final String PAGE="https://"+HOST+"/app/index.html", BASE="http://127.0.0.1:8766";
  private static WebCore webCore;
  private WebView web;
  private QaBrowser qaBrowser;
  private ScheduledExecutorService workers;
  private volatile boolean foreground=false, ready=false;
  private final AtomicBoolean sending=new AtomicBoolean(false);
  private String lastSnapshot="";
  private boolean reportedOffline=false;
  private String pendingExport=null, pendingReportId=null;

  @Override public void onCreate(Bundle saved) {
    super.onCreate(saved);
    if(webCore==null){webCore=new WebCore();webCore.start();}
    getWindow().setStatusBarColor(Color.rgb(8,13,23));
    getWindow().setNavigationBarColor(Color.rgb(8,13,23));
    getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
    web=new WebView(this);web.setBackgroundColor(Color.rgb(8,13,23));
    WebSettings settings=web.getSettings();settings.setJavaScriptEnabled(true);settings.setDomStorageEnabled(true);
    settings.setAllowFileAccess(false);settings.setAllowContentAccess(false);
    settings.setAllowFileAccessFromFileURLs(false);settings.setAllowUniversalAccessFromFileURLs(false);
    settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
    settings.setSupportMultipleWindows(false);settings.setJavaScriptCanOpenWindowsAutomatically(false);
    android.webkit.CookieManager.getInstance().setAcceptCookie(false);
    WebView.setWebContentsDebuggingEnabled(false);
    web.addJavascriptInterface(new Bridge(),"PocoNative");
    web.setWebViewClient(new WebViewClient(){
      @Override public WebResourceResponse shouldInterceptRequest(WebView view,WebResourceRequest request){return asset(request.getUrl());}
      @Override public boolean shouldOverrideUrlLoading(WebView view,WebResourceRequest request){
        Uri uri=request.getUrl();
        if("https".equals(uri.getScheme())&&HOST.equals(uri.getHost())&&"/app/index.html".equals(uri.getPath()))return false;
        if(request.isForMainFrame()&&("https".equals(uri.getScheme())||"http".equals(uri.getScheme()))) {
          try{startActivity(new Intent(Intent.ACTION_VIEW,uri));}catch(Exception ignored){Toast.makeText(MainActivity.this,"Nenhum navegador disponível.",Toast.LENGTH_SHORT).show();}
        }
        return true;
      }
      @Override public void onPageFinished(WebView view,String url){if(PAGE.equals(url))Log.i(TAG,"Bundled frontend loaded");}
      @Override public void onReceivedSslError(WebView view,android.webkit.SslErrorHandler handler,android.net.http.SslError error){handler.cancel();}
    });
    web.setWebChromeClient(new WebChromeClient(){
      @Override public boolean onConsoleMessage(ConsoleMessage message){if(message.messageLevel()==ConsoleMessage.MessageLevel.ERROR)Log.e(TAG,"Frontend error at line "+message.lineNumber()+": "+message.message());return true;}
    });
    qaBrowser=new QaBrowser(this,this::request);
    setContentView(web);web.loadUrl(PAGE);
    if(checkSelfPermission("com.termux.permission.RUN_COMMAND")!=PackageManager.PERMISSION_GRANTED)
      requestPermissions(new String[]{"com.termux.permission.RUN_COMMAND"},77);
  }
  private WebResourceResponse asset(Uri uri){
    try{
      if(!"https".equals(uri.getScheme())||!HOST.equals(uri.getHost()))throw new IOException();
      String path=uri.getPath();
      if(path==null||!path.startsWith("/app/"))throw new IOException();
      String file=path.substring(5);
      Set<String> allowed=new HashSet<>(Arrays.asList("index.html","styles.css","app.js","assets/cyber-mimo.png"));
      if(!allowed.contains(file))throw new IOException();
      String type=file.endsWith(".html")?"text/html":file.endsWith(".css")?"text/css":file.endsWith(".js")?"application/javascript":"image/png";
      Map<String,String> headers=new HashMap<>();
      headers.put("Content-Security-Policy","default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
      headers.put("X-Content-Type-Options","nosniff");headers.put("Cache-Control","no-cache");
      return new WebResourceResponse(type,"UTF-8",200,"OK",headers,getAssets().open("app/"+file));
    }catch(Exception ignored){return new WebResourceResponse("text/plain","UTF-8",403,"Blocked",Collections.emptyMap(),new ByteArrayInputStream(new byte[0]));}
  }
  @Override public void onRequestPermissionsResult(int code,String[] permissions,int[] grants){super.onRequestPermissionsResult(code,permissions,grants);if(code==77&&grants.length>0&&grants[0]==PackageManager.PERMISSION_GRANTED)startAgent();}
  private void startAgent(){
    if(checkSelfPermission("com.termux.permission.RUN_COMMAND")!=PackageManager.PERMISSION_GRANTED)return;
    try{
      Intent intent=new Intent("com.termux.RUN_COMMAND");intent.setClassName("com.termux","com.termux.app.RunCommandService");
      intent.putExtra("com.termux.RUN_COMMAND_PATH","/data/data/com.termux/files/usr/bin/bash");
      intent.putExtra("com.termux.RUN_COMMAND_ARGUMENTS",new String[]{"/data/data/com.termux/files/home/poco-agent/start.sh"});
      intent.putExtra("com.termux.RUN_COMMAND_BACKGROUND",true);
      intent.putExtra("com.termux.RUN_COMMAND_WORKDIR","/data/data/com.termux/files/home/poco-agent");startService(intent);
    }catch(Exception e){Log.w(TAG,"Open Termux to start the existing agent");}
  }
  @Override public void onResume(){super.onResume();foreground=true;qaBrowser.resume();lastSnapshot="";web.onResume();startAgent();workers=Executors.newScheduledThreadPool(2);workers.scheduleWithFixedDelay(this::poll,0,800,TimeUnit.MILLISECONDS);}
  @Override public void onPause(){foreground=false;qaBrowser.pause();web.onPause();if(workers!=null)workers.shutdownNow();super.onPause();}
  @Override public void onDestroy(){qaBrowser.destroy();ready=false;web.removeJavascriptInterface("PocoNative");web.destroy();super.onDestroy();}
  @Override public void onBackPressed(){web.evaluateJavascript("(()=>{const d=document.querySelector('dialog[open]');if(d){d.close();return true;}const b=document.querySelector('[data-view=chat]');if(b&&b.getAttribute('aria-current')!=='page'){b.click();return true;}return false;})()",result->{if(!"true".equals(result))moveTaskToBack(true);});}
  private void callback(String method,String arguments){runOnUiThread(()->{if(ready&&!isFinishing())web.evaluateJavascript("window.PocoHost&&window.PocoHost."+method+"("+arguments+")",null);});}
  private void result(String action,boolean ok,String message){callback("commandResult",JSONObject.quote(action)+","+ok+","+JSONObject.quote(message));}
  private void execute(Runnable task){ScheduledExecutorService pool=workers;if(pool!=null&&!pool.isShutdown())pool.execute(task);else result("send",false,"Reabra o aplicativo para reconectar.");}
  private String request(String path,String body)throws Exception{
    HttpURLConnection connection=(HttpURLConnection)new URL(BASE+path).openConnection(Proxy.NO_PROXY);
    connection.setConnectTimeout(3000);connection.setReadTimeout(path.startsWith("/api/browser/")?35000:5000);connection.setUseCaches(false);connection.setInstanceFollowRedirects(false);
    connection.setRequestProperty("Authorization","Bearer "+WebConfig.TOKEN);
    try{
      if(body!=null){connection.setRequestMethod("POST");connection.setDoOutput(true);connection.setRequestProperty("Content-Type","application/json");try(OutputStream out=connection.getOutputStream()){out.write(body.getBytes(StandardCharsets.UTF_8));}}
      int code=connection.getResponseCode();InputStream stream=code<400?connection.getInputStream():connection.getErrorStream();ByteArrayOutputStream bytes=new ByteArrayOutputStream();
      if(stream!=null)try(InputStream in=stream){byte[] chunk=new byte[4096];int n;while((n=in.read(chunk))!=-1){bytes.write(chunk,0,n);if(bytes.size()>2000000)throw new IOException("Resposta excedeu o limite.");}}
      String text=new String(bytes.toByteArray(),StandardCharsets.UTF_8);
      if(code>=400){String detail=code==409?"O agente já está trabalhando.":code==403?"A autenticação do agente falhou.":"O agente recusou o pedido (HTTP "+code+").";throw new IOException(detail);}
      return text;
    }finally{connection.disconnect();}
  }
  private void poll(){
    if(!foreground||!ready||sending.get())return;
    try{
      JSONObject snapshot=publicSnapshot(new JSONObject(request("/api/state",null)));
      runOnUiThread(()->{if(snapshot.optBoolean("active"))getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);});
      String json=snapshot.toString();
      if(reportedOffline){reportedOffline=false;callback("connection","true,\"\"");}
      if(json.equals(lastSnapshot))return;lastSnapshot=json;
      runOnUiThread(()->{if(ready&&foreground)web.evaluateJavascript("window.PocoHost&&window.PocoHost.receive("+json+")",reply->Log.i(TAG,"Public state rendered: "+reply));});
    }catch(Exception e){if(!reportedOffline){reportedOffline=true;callback("connection","false,\"Abra o Termux para iniciar o agente local.\"");Log.w(TAG,"Agent connection unavailable");}}
  }
  private static String publicText(String value){return value.replaceAll("(?is)<think\\b[^>]*>.*?(?:</think\\s*>|$)","").trim();}
  private static void fields(JSONObject from,JSONObject to,String...keys)throws JSONException{
    for(String key:keys){Object value=from.opt(key);if(value instanceof String)to.put(key,((String)value).substring(0,Math.min(((String)value).length(),16000)));else if(value instanceof Number||value instanceof Boolean)to.put(key,value);}
  }
  private static JSONArray sources(JSONArray source)throws JSONException{
    JSONArray result=new JSONArray();if(source==null)return result;
    for(int i=0;i<Math.min(source.length(),60);i++){JSONObject row=source.optJSONObject(i);if(row==null)continue;JSONObject safe=new JSONObject();fields(row,safe,"url","title","excerpt");result.put(safe);}return result;
  }
  static JSONObject publicSnapshot(JSONObject raw)throws JSONException{
    JSONObject safe=new JSONObject();fields(raw,safe,"phase","prompt","scope","active","source","updated_at","decision","elapsed_seconds","error","learning_message","learning_kind","learning_seq","request_id");
    safe.put("content",publicText(raw.optString("content","")));
    JSONObject evidence=raw.optJSONObject("evidence");JSONObject publicEvidence=new JSONObject();JSONArray steps=new JSONArray();
    if(evidence!=null){
      publicEvidence.put("sources",sources(evidence.optJSONArray("sources")));
      JSONArray original=evidence.optJSONArray("steps");
      if(original!=null)for(int i=0;i<Math.min(original.length(),100);i++){
        JSONObject step=original.optJSONObject(i);if(step==null)continue;JSONObject output=new JSONObject();
        fields(step,output,"tool","url","status","returncode","timed_out","execution_complete","confirmation_status","content_type","markup_injected","marker_reflected","database_error_indication","boolean_candidate","reported_injection","reported_dbms","request_count","false_positive_check","data_extraction_performed","selected_template_count");
        JSONObject counts=step.optJSONObject("coverage"),safeCounts=new JSONObject();
        if(counts!=null)fields(counts,safeCounts,"discovered","visited","analyzed","pending","failed","blocked");
        output.put("coverage",safeCounts);fields(step,output,"javascript_executed","requests","javascript_pages","browser_errors","queue_exhausted","inventory_complete");
        JSONArray hypotheses=step.optJSONArray("hypotheses"),safeHypotheses=new JSONArray();
        if(hypotheses!=null)for(int h=0;h<Math.min(hypotheses.length(),60);h++){JSONObject entry=hypotheses.optJSONObject(h);if(entry==null)continue;JSONObject cleanHypothesis=new JSONObject();fields(entry,cleanHypothesis,"hypothesis","url","signal","status","impact","verification","severity","recommendation","evidence");safeHypotheses.put(cleanHypothesis);}
        output.put("hypotheses",safeHypotheses);
        fields(step,output,"job_id","findings_total","findings_omitted","pages_total","pages_omitted","checks_catalog","assessment","not_tested");
        JSONArray pages=step.optJSONArray("pages"),safePages=new JSONArray();
        if(pages!=null)for(int p=0;p<Math.min(pages.length(),100);p++){JSONObject entry=pages.optJSONObject(p);if(entry==null)continue;JSONObject cleanPage=new JSONObject();fields(entry,cleanPage,"url","state","status","error","truncated");safePages.put(cleanPage);}
        output.put("pages",safePages);
        JSONObject learning=step.optJSONObject("learning"),safeLearning=new JSONObject();
        if(learning!=null)fields(learning,safeLearning,"saved","previous_runs","runs","new_routes","reproduced_observations","recurring_observations","memory_limited","message");
        output.put("learning",safeLearning);
        output.put("sources",sources(step.optJSONArray("sources")));
        JSONArray findings=step.optJSONArray("findings"),clean=new JSONArray();
        if(findings!=null)for(int j=0;j<Math.min(findings.length(),20);j++){JSONObject finding=findings.optJSONObject(j);if(finding==null)continue;JSONObject f=new JSONObject();fields(finding,f,"template-id","matched-at","matcher-name");JSONObject info=finding.optJSONObject("info"),infoSafe=new JSONObject();if(info!=null)fields(info,infoSafe,"name","severity","description");f.put("info",infoSafe);clean.put(f);}output.put("findings",clean);steps.put(output);
      }
    }
    publicEvidence.put("steps",steps);safe.put("evidence",publicEvidence);return safe;
  }
  public final class Bridge {
    @JavascriptInterface public void ready(){ready=true;lastSnapshot="";Log.i(TAG,"Frontend bridge ready");runOnUiThread(()->web.evaluateJavascript("JSON.stringify({native:!!window.PocoHost,images:document.images.length,mascot:!!document.querySelector('.mascot-character'),docs:!!document.querySelector('#view-docs')})",value->Log.i(TAG,"Frontend startup: "+value)));}
    @JavascriptInterface public String savedScope(){return getPreferences(0).getString("scope","");}
    @JavascriptInterface public void sendMessage(String payload){
      if(!sending.compareAndSet(false,true)){result("send",false,"Aguarde o envio anterior.");return;}
      execute(()->{try{
        JSONObject input=new JSONObject(payload);String prompt=input.optString("prompt","").trim(),scope=input.optString("scope","").trim();
        if(prompt.isEmpty()||prompt.length()>2000||scope.length()>2000)throw new IOException("Use até 2.000 caracteres por campo.");
        if(!scope.isEmpty()){URI url=new URI(scope);if(!Arrays.asList("http","https").contains(url.getScheme())||url.getHost()==null||url.getUserInfo()!=null)throw new IOException("Informe um link HTTP ou HTTPS válido, sem credenciais.");}
        JSONObject body=new JSONObject().put("prompt",prompt).put("scope",scope).put("thinking",false);
        String requestId=input.optString("request_id","");if(requestId.matches("[a-f0-9-]{36}"))body.put("request_id",requestId);
        request("/api/chat",body.toString());getPreferences(0).edit().putString("scope",scope).apply();lastSnapshot="";result("send",true,"");
      }catch(Exception e){result("send",false,e.getMessage()==null?"Não foi possível enviar.":e.getMessage());}finally{sending.set(false);}});
    }
    @JavascriptInterface public void stop(){execute(()->{try{request("/api/stop","{}");result("stop",true,"");}catch(Exception e){result("stop",false,"Não foi possível interromper; confira a conexão.");}});}
    @JavascriptInterface public void exportSecurityReport(String id){
      if(id==null||!id.matches("[a-f0-9]{32}"))return;
      runOnUiThread(()->{if(pendingExport!=null||pendingReportId!=null){result("export",false,"Conclua o salvamento anterior.");return;}pendingReportId=id;Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);intent.addCategory(Intent.CATEGORY_OPENABLE);intent.setType("application/json");intent.putExtra(Intent.EXTRA_TITLE,"mimo-seguranca-"+id+".json");startActivityForResult(intent,91);});
    }
    @JavascriptInterface public void saveDocument(String name,String type,String content){
      if(content==null||content.length()>1000000||!Arrays.asList("text/markdown","application/json").contains(type))return;
      runOnUiThread(()->{if(pendingExport!=null||pendingReportId!=null){result("export",false,"Conclua o salvamento anterior.");return;}pendingExport=content;Intent intent=new Intent(Intent.ACTION_CREATE_DOCUMENT);intent.addCategory(Intent.CATEGORY_OPENABLE);intent.setType(type);String fileName=name.replaceAll("[^a-zA-Z0-9._-]","_");intent.putExtra(Intent.EXTRA_TITLE,fileName.substring(0,Math.min(fileName.length(),150)));startActivityForResult(intent,90);});
    }
  }
  @Override protected void onActivityResult(int request,int resultCode,Intent data){super.onActivityResult(request,resultCode,data);
    if(request==91){String id=pendingReportId;pendingReportId=null;
      if(resultCode!=RESULT_OK||data==null||data.getData()==null||id==null){result("export",false,"Salvamento cancelado.");return;}
      Uri destination=data.getData();new Thread(()->{HttpURLConnection connection=null;try{
        connection=(HttpURLConnection)new URL(BASE+"/api/security-report/"+id).openConnection(Proxy.NO_PROXY);
        connection.setConnectTimeout(3000);connection.setReadTimeout(10000);connection.setInstanceFollowRedirects(false);
        connection.setRequestProperty("Authorization","Bearer "+WebConfig.TOKEN);
        if(connection.getResponseCode()!=200)throw new IOException("Relatório ainda não disponível.");
        try(InputStream in=connection.getInputStream();OutputStream out=getContentResolver().openOutputStream(destination)){if(out==null)throw new IOException();byte[] chunk=new byte[65536];int n;while((n=in.read(chunk))!=-1)out.write(chunk,0,n);}
        result("export",true,"Relatório completo salvo.");
      }catch(Exception e){result("export",false,"Falha ao salvar; o arquivo pode estar incompleto. Tente novamente.");}finally{if(connection!=null)connection.disconnect();}},"mimo-report-export").start();return;}
    if(request!=90)return;String content=pendingExport;pendingExport=null;
    if(resultCode!=RESULT_OK||data==null||data.getData()==null){result("export",false,"Salvamento cancelado.");return;}
    try(OutputStream out=getContentResolver().openOutputStream(data.getData())){if(content==null||out==null)throw new IOException();out.write(content.getBytes(StandardCharsets.UTF_8));result("export",true,"Arquivo salvo.");}catch(Exception e){result("export",false,"Não foi possível salvar o arquivo.");}
  }
}

package local.poco.ai;

import org.jsoup.Jsoup;
import org.jsoup.nodes.*;
import java.text.Normalizer;
import org.json.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

final class WebCore {
 private final ThreadPoolExecutor pool=new ThreadPoolExecutor(2,2,30,TimeUnit.SECONDS,new ArrayBlockingQueue<Runnable>(4));
 private final Object rateLock=new Object();
 private long lastFetch=0;
 void start(){Thread thread=new Thread(()->{
  try{ServerSocket server=new ServerSocket();server.setReuseAddress(true);server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),8767));
   while(true){Socket client=server.accept();try{pool.execute(()->handle(client));}catch(RejectedExecutionException e){client.close();}}
  }catch(IOException e){android.util.Log.e("PocoWebCore","Local web tool unavailable",e);}
 },"PocoWebCore");thread.setDaemon(true);thread.start();}
 private static String clip(String s,int n){return s.length()>n?s.substring(0,n):s;}
 private static void send(Socket socket,int code,JSONObject data)throws IOException{
  byte[] bytes=data.toString().getBytes(StandardCharsets.UTF_8);OutputStream out=socket.getOutputStream();
  out.write(("HTTP/1.1 "+code+" Response\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: "+bytes.length+"\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n").getBytes(StandardCharsets.US_ASCII));out.write(bytes);out.flush();
 }
 private void handle(Socket socket){try{Socket s=socket;s.setSoTimeout(20000);InputStream in=s.getInputStream();ByteArrayOutputStream header=new ByteArrayOutputStream();int tail=0;
  while(header.size()<8192){int b=in.read();if(b<0)throw new IOException("Incomplete headers");header.write(b);tail=(tail<<8)|b;if(tail==0x0d0a0d0a)break;}
  if(tail!=0x0d0a0d0a)throw new IOException("Headers too large");String[] lines=new String(header.toByteArray(),StandardCharsets.US_ASCII).split("\r\n");String[] first=lines[0].split(" ");
  Map<String,String> fields=new HashMap<>();for(int i=1;i<lines.length;i++){int x=lines[i].indexOf(':');if(x>0){String k=lines[i].substring(0,x).toLowerCase(Locale.ROOT);if(fields.put(k,lines[i].substring(x+1).trim())!=null)throw new IOException("Duplicate header");}}
  if(!("Bearer "+WebConfig.TOKEN).equals(fields.get("authorization"))||fields.containsKey("origin")){send(s,403,new JSONObject().put("error","Unauthorized"));return;}
  if(first.length!=3){send(s,400,new JSONObject().put("error","Invalid request"));return;}
  if(first[0].equals("GET")&&first[1].equals("/health")){send(s,200,new JSONObject().put("status","ok").put("executor","Android").put("engine","jsoup 1.24.1").put("external_search_api",false));return;}
  if(!first[0].equals("POST")||fields.containsKey("transfer-encoding")||!"application/json".equals(fields.get("content-type"))){send(s,400,new JSONObject().put("error","Expected JSON POST"));return;}
  int length=Integer.parseInt(fields.getOrDefault("content-length","0"));if(length<1||length>12000)throw new IOException("Invalid body size");byte[] body=new byte[length];int at=0;while(at<length){int n=in.read(body,at,length-at);if(n<0)throw new IOException("Incomplete body");at+=n;}
  JSONObject input=new JSONObject(new String(body,StandardCharsets.UTF_8));JSONObject result;
  if(first[1].equals("/crawl"))result=crawl(input);
  else if(first[1].equals("/read"))result=readPage(input.getString("url"));
  else {send(s,404,new JSONObject().put("error","Unknown tool"));return;}
  send(s,200,result);
 }catch(Exception e){try{if(!socket.isClosed())send(socket,502,new JSONObject().put("error",clip(e.getMessage()==null?"Web tool failed":e.getMessage(),250)));}catch(Exception ignored){}}finally{try{socket.close();}catch(IOException ignored){}}
 }
 static void publicUrl(URL u)throws Exception{
  if(!u.getProtocol().equals("https"))throw new IOException("Public source reader requires HTTPS");
  if(u.getUserInfo()!=null||u.getHost().isEmpty()||u.toString().length()>3000)throw new IOException("Invalid public URL");
  int port=u.getPort();if(port!=-1&&port!=443)throw new IOException("Only public web ports are allowed");
  for(InetAddress a:InetAddress.getAllByName(u.getHost())){
   if(a.isAnyLocalAddress()||a.isLoopbackAddress()||a.isLinkLocalAddress()||a.isSiteLocalAddress()||a.isMulticastAddress())throw new IOException("Private addresses are not web sources");
   byte[] b=a.getAddress();int x=b[0]&255;
   if(b.length==4&&(x==0||x>=224||(x==100&&((b[1]&255)>=64&&(b[1]&255)<=127))||(x==198&&((b[1]&255)==18||(b[1]&255)==19))))throw new IOException("Reserved address");
   if(b.length==16&&(x&254)==252)throw new IOException("Private IPv6 address");
  }
 }
 private JSONObject fetch(String address,int limit)throws Exception{
  synchronized(rateLock){long now=android.os.SystemClock.elapsedRealtime();long pause=1000-(now-lastFetch);if(pause>0)Thread.sleep(pause);lastFetch=android.os.SystemClock.elapsedRealtime();}
  URL url=new URL(address.startsWith("http://")?"https://"+address.substring(7):address);
  for(int hop=0;hop<4;hop++){
   publicUrl(url);HttpURLConnection c=(HttpURLConnection)url.openConnection(Proxy.NO_PROXY);c.setConnectTimeout(12000);c.setReadTimeout(18000);c.setInstanceFollowRedirects(false);c.setRequestProperty("User-Agent","PocoAITerminal/1.2 (public-source reader)");c.setRequestProperty("Accept-Encoding","identity");
   try{int code=c.getResponseCode();if(code>=300&&code<400){String location=c.getHeaderField("Location");if(location==null)throw new IOException("Redirect without location");url=new URL(url,location);continue;}
    if(code<200||code>=300)throw new IOException("Source HTTP "+code);
    String type=c.getContentType();if(type==null)type="";if(!(type.contains("text/")||type.contains("json")||type.contains("xml")))throw new IOException("Source is not readable text");
    ByteArrayOutputStream bytes=new ByteArrayOutputStream();boolean truncated=false;try(InputStream input=c.getInputStream()){byte[] chunk=new byte[8192];int n;while((n=input.read(chunk))!=-1){int take=Math.min(n,limit-bytes.size());if(take>0)bytes.write(chunk,0,take);if(bytes.size()>=limit){truncated=true;break;}}}
    return new JSONObject().put("url",url.toString()).put("type",type).put("body",new String(bytes.toByteArray(),StandardCharsets.UTF_8)).put("truncated",truncated);
   }finally{c.disconnect();}
  }throw new IOException("Too many redirects");
 }

 private static Set<String> terms(String query){
  Set<String> words=new HashSet<>();String normalized=Normalizer.normalize(query.toLowerCase(Locale.ROOT),Normalizer.Form.NFD).replaceAll("\\p{M}","");
  for(String word:normalized.split("[^a-z0-9]+"))if(word.length()>2&&!Arrays.asList("para","como","que","com","uma","the","and","das","dos","https","www").contains(word))words.add(word);
  return words;
 }
 private static int score(String text,Set<String> words){String n=Normalizer.normalize(text.toLowerCase(Locale.ROOT),Normalizer.Form.NFD).replaceAll("\\p{M}","");int score=0;for(String w:words)if(n.contains(w))score++;return score;}
 private JSONObject page(String address,String query)throws Exception{
  JSONObject raw=fetch(address,600000);Document doc=Jsoup.parse(raw.getString("body"),raw.getString("url"));
  JSONArray links=new JSONArray();Set<String> seen=new HashSet<>();Set<String> words=terms(query);
  for(Element a:doc.select("a[href]")){
   String url=a.absUrl("href").split("#",2)[0];
   if(!url.startsWith("https://")||url.length()>2500||a.attr("rel").contains("nofollow")||!seen.add(url))continue;
   if(url.matches("(?i).*\\.(pdf|zip|gz|exe|apk|jpg|png|svg|mp4)(\\?.*)?$"))continue;
   links.put(new JSONObject().put("url",url).put("title",clip(a.text(),160)).put("score",score(a.text()+" "+url,words)));
   if(links.length()>=150)break;
  }
  doc.select("script,style,noscript,nav,header,footer,aside,form,svg").remove();
  List<String> paragraphs=new ArrayList<>();Set<String> unique=new HashSet<>();
  for(Element e:doc.select("h1,h2,h3,p,li,pre")){String t=e.text().trim();if(t.length()>30&&unique.add(t))paragraphs.add(clip(t,900));}
  if(paragraphs.isEmpty())paragraphs.add(clip(doc.text(),900));
  List<Integer> order=new ArrayList<>();for(int i=0;i<paragraphs.size();i++)order.add(i);
  order.sort((a,b)->Integer.compare(score(paragraphs.get(b),words),score(paragraphs.get(a),words)));
  List<Integer> chosen=new ArrayList<>(order.subList(0,Math.min(3,order.size())));Collections.sort(chosen);
  StringBuilder excerpt=new StringBuilder();for(int i:chosen)excerpt.append(paragraphs.get(i)).append("\n");
  return new JSONObject().put("url",raw.getString("url")).put("title",clip(doc.title(),160)).put("executor","Android")
   .put("retrieved_at",System.currentTimeMillis()/1000).put("excerpt",clip(excerpt.toString().trim(),1100))
   .put("truncated",raw.getBoolean("truncated")||doc.text().length()>1100).put("links",links);
 }
 private JSONObject readPage(String address)throws Exception{JSONObject p=page(address,"");p.remove("links");return p;}
 private JSONObject crawl(JSONObject input)throws Exception{
  String query=input.getString("query").trim();if(query.isEmpty()||query.length()>500)throw new IOException("Query must have 1 to 500 characters");
  JSONArray seeds=input.getJSONArray("urls");if(seeds.length()<1||seeds.length()>2)throw new IOException("Provide one or two seed URLs");
  int budget=Math.max(1,Math.min(3,input.optInt("max_pages",3)));
  List<JSONObject> frontier=new ArrayList<>();Set<String> hosts=new HashSet<>();Set<String> seen=new HashSet<>();
  for(int i=0;i<seeds.length();i++){String url=seeds.getString(i);URL parsed=new URL(url);publicUrl(parsed);hosts.add(parsed.getHost());frontier.add(new JSONObject().put("url",url).put("score",1000).put("depth",0));}
  JSONArray pages=new JSONArray(),errors=new JSONArray();int attempts=0;long started=android.os.SystemClock.elapsedRealtime();
  while(!frontier.isEmpty()&&attempts<budget&&android.os.SystemClock.elapsedRealtime()-started<75000){
   frontier.sort((a,b)->Integer.compare(b.optInt("score"),a.optInt("score")));
   JSONObject item=frontier.remove(0);String address=item.getString("url");if(!seen.add(address))continue;attempts++;
   try{JSONObject p=page(address,query);JSONArray links=p.getJSONArray("links");
    // Follow only relevant links on seed hosts, with bounded depth and total requests.
    if(item.optInt("depth")<2)for(int i=0;i<links.length()&&frontier.size()<30;i++){
     JSONObject link=links.getJSONObject(i);String next=link.getString("url");
     if(link.optInt("score")>0&&!seen.contains(next)&&hosts.contains(new URL(next).getHost()))frontier.add(new JSONObject(link.toString()).put("depth",item.optInt("depth")+1));
    }
    p.remove("links");pages.put(p);
   }catch(Exception e){errors.put(new JSONObject().put("url",address).put("error",clip(String.valueOf(e.getMessage()),200)));}
  }
  return new JSONObject().put("executor","Android").put("engine","jsoup 1.24.1").put("external_search_api",false)
   .put("query",query).put("attempts",attempts).put("sources",pages).put("errors",errors)
   .put("limitations","Bounded HTML crawl from seed URLs; no whole-web index or JavaScript execution. Extracts use keyword relevance.");
 }
}

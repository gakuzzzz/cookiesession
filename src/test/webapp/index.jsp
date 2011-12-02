<p>Hello World</p>

<%
	int count = 0;
	Integer counter = (Integer) session.getAttribute("counter");
	if (counter == null) {
		session.setAttribute("date", new java.util.Date());
%>
<p>start count</p>
<%
	} else {
		count = counter.intValue();
		count++;
	}
	session.setAttribute("counter", Integer.valueOf(count));
	java.util.Date d = (java.util.Date) session.getAttribute("date");
%>
<p><%= count %></p>
<p><%= new java.text.SimpleDateFormat("HH:mm:ss").format(d) %></p>
<p><%= session.getCreationTime() %></p>
<p><%= session.getLastAccessedTime() %></p>
<%
	if (count > 20) {
		session.invalidate();
	}
%>
